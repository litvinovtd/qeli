package com.qeli

import android.Manifest
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.SharedPreferences
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.Uri
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.PowerManager
import android.provider.Settings
import android.text.InputType
import android.util.Log
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.CheckBox
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.ViewModelProvider
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.google.android.material.tabs.TabLayout
import com.qeli.databinding.ActivityMainBinding
import com.qeli.databinding.ItemProfileBinding
import com.qeli.databinding.DialogConfigEditorBinding
import com.qeli.model.ProtectionScope
import com.qeli.model.ProtectionSummary
import com.qeli.model.ProtectionWarning
import com.qeli.model.VpnConfig
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.atomic.AtomicLong
import kotlin.coroutines.resume

class MainActivity : AppCompatActivity() {

    // Force the chosen UI language (default English) before any resource is loaded, so it
    // overrides the device locale from the very first frame. recreate() re-runs this.
    override fun attachBaseContext(newBase: Context) {
        super.attachBaseContext(QeliApp.wrap(newBase))
    }

    // AppCompat 1.6+ rebuilds a Configuration here for night mode and, in doing so, resets
    // the locale back to the device's — undoing attachBaseContext. Re-assert our forced
    // locale by copying the base (wrapped) config, keeping only AppCompat's uiMode.
    override fun applyOverrideConfiguration(overrideConfiguration: android.content.res.Configuration?) {
        if (overrideConfiguration != null) {
            val uiMode = overrideConfiguration.uiMode
            overrideConfiguration.setTo(baseContext.resources.configuration)
            overrideConfiguration.uiMode = uiMode
        }
        super.applyOverrideConfiguration(overrideConfiguration)
    }

    private lateinit var binding: ActivityMainBinding
    private var isConnected = false
    // True while a connect/reconnect attempt is in flight (STATUS_CONNECTING) but not
    // yet established. The connect ring is a toggle: tapping it during this phase must
    // CANCEL the attempt, otherwise a server that keeps closing the connection leaves
    // the client retrying forever with no way to stop it from the UI.
    private var isConnecting = false
    // No TUN is installed, but the foreground controller is intentionally alive and will
    // restore the selected profile after leaving a trusted Wi-Fi network.
    private var isTrustedPaused = false
    // Native owns duplicated TUN descriptors. This state remains busy until the service
    // confirms that its runner has exited and Android routes/DNS are actually restored.
    private var isDisconnecting = false
    // Invalidates reachability probes launched against a VPN generation being torn down.
    private var reachEpoch = 0L
    private var clientIp = ""
    private var clientGateway = ""
    private var logLineCount = 0
    private val diagnosticJournal by lazy { AndroidDiagnosticJournal.get(noBackupFilesDir) }
    private var logRestoreJob: Job? = null
    private var restoringLog = false
    private var displayedLogEpoch = 0L
    private var restoredThroughSequence = 0L
    private val restoreLiveRecords = ArrayDeque<JournalRecord>()
    private var reportJob: Job? = null
    private var pendingReport: ByteArray? = null
    private var pendingReportEpoch = -1L
    private var pendingReportPrivacyRevision = -1L
    private var reportExpiryJob: Job? = null
    // Mirror of PREF_LOG_TIME_FORMAT, cached because appendLog reads it per line.
    // Refreshed in onCreate and whenever Settings is saved.
    private var logTimeFormat = DEFAULT_LOG_TIME_FORMAT
    private val connectRequest by lazy {
        ViewModelProvider(this)[VpnConnectViewModel::class.java].request
    }
    private var logAutoScroll = true
    // True while a fullScroll is already queued on scrollLog, so a burst of log lines
    // coalesces into a single scroll per frame instead of one layout pass per line.
    private var pendingLogScroll = false
    private var ringSpin: android.animation.ObjectAnimator? = null
    private var autoProbeJob: Job? = null
    private val automaticProbeJobs = java.util.Collections.synchronizedSet(mutableSetOf<Job>())
    private val reachabilityProbeSlots = kotlinx.coroutines.sync.Semaphore(4)
    private var lastAutoProbeAtMs = 0L

    private val profiles = mutableListOf<Profile>()
    private var activeIndex = 0
    private var profileStoreLoadRejected = false
    private var observedProfileVersion: ProfileStore.SecureStore.Version? = null
    private var profileRevision = 0L
    private val reach = HashMap<Int, Long>()   // profile index -> ping ms (-1 = down, -2 = checking)

    /** Encrypted-at-rest profile store: profiles carry the server password and
     *  obfs_key, so they must not sit in plaintext SharedPreferences. The master
     *  key lives in the Android Keystore (TEE/StrongBox where available). On first
     *  use this migrates any legacy plaintext profiles, then wipes the legacy copy
     *  so secrets no longer linger unencrypted. (docs/ru/archive/plans/RELEASE-FIXES.md E1) */
    private val secureStore: ProfileStore.SecureStore by lazy {
        // Same store the Quick Settings tile reads — see ProfileStore for the shared params.
        val store = ProfileStore.open(this)
        // Preserve a failed encrypted migration and its revision for explicit backup
        // restore; an older plaintext copy must not turn it into an ordinary write.
        if (store.legacyMigrationFailure != null) return@lazy store
        val legacy = getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        if (!store.contains(KEY_PROFILES)) {
            legacy.getString(KEY_PROFILES, null)?.let { raw ->
                check(store.edit().putString(KEY_PROFILES, raw).commit()) {
                    "Could not commit migrated profile store"
                }
                check(store.getString(KEY_PROFILES, null) == raw) {
                    "Migrated profile store did not pass read-back verification"
                }
            }
        }
        if (legacy.contains(KEY_PROFILES)) {
            // Preserve the plaintext recovery copy if the encrypted entry is unreadable.
            check(store.getString(KEY_PROFILES, null) != null) {
                "Encrypted profile store is absent; refusing to erase legacy profiles"
            }
            check(legacy.edit().remove(KEY_PROFILES).commit()) {
                "Could not erase legacy plaintext profiles"
            }
        }
        store
    }

    /** A saved profile. [text] is flat-INI (the `[qeli]` schema). */
    private data class Profile(var name: String, var text: String)

    companion object {
        private const val MAX_LOG_LINES = DiagnosticLogStore.MAX_ENTRIES
        private const val PREFS_NAME = "vpn"
        private const val KEY_PROFILES = "profiles_json"
        /** Intent extra: the Quick Settings tile ([QeliTileService]) sets this to true to ask
         *  the Activity to connect the active profile (it owns the consent / permission flows). */
        const val EXTRA_AUTO_CONNECT = "auto_connect"
        // App-state prefs (non-secret) shared with the boot receiver.
        const val PREFS_STATE = "app_state"
        const val PREF_AUTO_CONNECT_LAUNCH = "auto_connect_launch"
        const val PREF_AUTO_CONNECT_BOOT = "auto_connect_boot"
        const val PREF_TRUSTED_WIFI_ENABLED = "trusted_wifi_enabled"
        const val PREF_TRUSTED_WIFI_SSIDS = "trusted_wifi_ssids"
        const val PREF_CONNECTION_DESIRED = "connection_desired"
        const val PREF_DIAGNOSTIC_SESSION_ID = "diagnostic_session_id"
        // Global LAN-bypass toggle (read by QeliService at establish; OR'd with the
        // profile's own allow_lan). Lets Wi-Fi/LAN devices stay reachable on a full tunnel.
        const val PREF_ALLOW_LAN = "allow_lan"
        // Timestamp shape in the log view. Same value names as the server's
        // [logging] time_format. The default stays "time" — that is what this app
        // has always shown, and a full date on every line eats a phone-width row.
        const val PREF_LOG_TIME_FORMAT = "log_time_format"
        const val DEFAULT_LOG_TIME_FORMAT = "time"
        const val PREF_LOG_LEVEL = "log_level"
        const val DEFAULT_LOG_LEVEL = "info"
        const val PREF_CLEAR_LOG_ON_DISCONNECT = "clear_log_on_disconnect"
        const val PREF_RETAIN_ERROR_REPORT = "retain_error_report"
        const val DEFAULT_CLEAR_LOG_ON_DISCONNECT = true
        const val PREF_AUTO_PROBE = "auto_probe_profiles"
        const val PREF_PROBE_INTERVAL_SECS = "probe_interval_secs"
        /** True only while this process has a started Activity. The VPN service uses this
         * to add the location foreground-service type during a user-visible transition;
         * Android 14 rejects adding that while-in-use type to a service created in the
         * background, even when checkSelfPermission still reports GRANTED. */
        @Volatile
        internal var uiVisible = false
            private set
        private const val PREF_LAST_AUTO_PROBE_MS = "last_auto_probe_ms"
        private const val MAX_IMPORTED_FILE_BYTES = ProfileStore.MAX_PROFILE_SET_BYTES
        // QELI-ENC-1 base64-expands an otherwise valid 8 MiB plaintext archive.
        private const val MAX_IMPORTED_BACKUP_BYTES = com.qeli.crypto.BackupCrypto.MAX_BACKUP_BYTES
        private const val MAX_IMPORTED_CONFIG_BYTES = 256 * 1024 // shared editor/native core limit
        private const val MAX_IMPORTED_PROFILES = ProfileStore.MAX_PROFILES
        private const val MAX_IMPORTED_PROFILE_NAME_CHARS = 256
        private val REACHABILITY_PROBE_IDS = AtomicLong(0L)
        // Flat-INI template — the same `[qeli]` schema the Rust client reads.
        private const val TEMPLATE = """# My server
[qeli]
server = SERVER_IP_OR_HOST:443
proto = tcp
user = phone
pass = changeme
key =
mode = fake-tls
sni = www.microsoft.com
ipv6 = auto
# allow_ipv4_leak = false ; full-tunnel exception for an IPv6-only plan
# allow_ipv6_leak = false ; full-tunnel exception for an IPv4-only plan
# kill_switch = true       ; requires Android Always-on VPN + Block without VPN
# route_local = false      ; route LAN/RFC1918 through the tunnel
# dns_servers = 1.1.1.1, 8.8.8.8 ; resolvers reached via the tunnel
"""
    }

    private val vpnPrepareLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { r ->
        val granted = r.resultCode == RESULT_OK
        if (connectRequest.finishPermission(VpnConnectRequest.Permission.VPN, granted)) {
            if (granted) startVpnService()
            else { appendLog("VPN permission denied"); setDisconnectedState() }
        }
    }

    private val importConfigLauncher = registerForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri -> if (uri != null) importConfigFromUri(uri) }

    private val qrScanLauncher = registerForActivityResult(ScanContract()) { result ->
        result.contents?.let { addProfileFromQeliUri(it) }
    }

    private val notificationPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { granted ->
        if (connectRequest.finishPermission(VpnConnectRequest.Permission.NOTIFICATION, granted)) {
            if (granted) proceedWithVpnPermission()
            else { appendLog("Notification permission denied - required for VPN"); setDisconnectedState() }
        }
    }

    private val trustedWifiPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions()
    ) { grants ->
        if (grants.values.any { granted -> !granted }) {
            Toast.makeText(this, R.string.trusted_wifi_permission_denied, Toast.LENGTH_LONG).show()
        }
        // A denial can turn an SSID that was previously known into UNKNOWN. Re-evaluate even
        // then so the service resumes instead of leaving VPN suppressed on unverifiable trust.
        reevaluateTrustedWifi()
    }

    // Backup/restore ALL profiles via the Storage Access Framework (a plain JSON file the
    // user picks the location for). NB: the file carries server passwords in the clear —
    // the same trade-off as WireGuard's config export.
    private val backupLauncher = registerForActivityResult(
        ActivityResultContracts.CreateDocument("application/json")
    ) { uri -> if (uri != null) writeBackup(uri) }

    private val restoreLauncher = registerForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri -> if (uri != null) readRestore(uri) }

    private val diagnosticExportLauncher = registerForActivityResult(
        ActivityResultContracts.CreateDocument("application/json")
    ) { uri ->
        val bytes = pendingReport
        val exportEpoch = pendingReportEpoch
        val privacyRevision = pendingReportPrivacyRevision
        pendingReport = null
        reportExpiryJob?.cancel()
        if (uri == null) { bytes?.fill(0) }
        else if (bytes == null || exportEpoch != diagnosticJournal.epoch ||
            privacyRevision != diagnosticJournal.privacyRevision) {
            bytes?.fill(0)
            Toast.makeText(this, R.string.report_expired, Toast.LENGTH_LONG).show()
        } else {
            reportJob = lifecycleScope.launch {
                if (!diagnosticJournal.tryStartExternalExport()) {
                    bytes.fill(0)
                    Toast.makeText(this@MainActivity, R.string.report_failed, Toast.LENGTH_LONG).show()
                    return@launch
                }
                val saved = try {
                    withContext(Dispatchers.IO) {
                        try {
                            check(exportEpoch == diagnosticJournal.epoch &&
                                privacyRevision == diagnosticJournal.privacyRevision)
                            contentResolver.openOutputStream(uri, "wt")?.use {
                                check(exportEpoch == diagnosticJournal.epoch &&
                                    privacyRevision == diagnosticJournal.privacyRevision)
                                it.write(bytes)
                            } ?: error("No output stream")
                            true
                        } catch (_: Exception) { false }
                        finally { bytes.fill(0) }
                    }
                } finally {
                    bytes.fill(0)
                    diagnosticJournal.finishExternalExport()
                }
                Toast.makeText(this@MainActivity, if (saved) R.string.report_saved else R.string.report_failed,
                    Toast.LENGTH_LONG).show()
            }
        }
    }

    private val statusReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            val status = intent.getStringExtra(VpnServiceImpl.EXTRA_STATUS)
            val error = intent.getStringExtra(VpnServiceImpl.EXTRA_ERROR)
            val log = intent.getStringExtra(VpnServiceImpl.EXTRA_LOG)
            val logTimeMs = intent.getLongExtra(
                VpnServiceImpl.EXTRA_LOG_TIME_MS,
                System.currentTimeMillis(),
            )
            val logSessionId = intent.getStringExtra(VpnServiceImpl.EXTRA_LOG_SESSION_ID).orEmpty()
            val logLevel = intent.getStringExtra(VpnServiceImpl.EXTRA_LOG_LEVEL) ?: "info"
            val logEpoch = intent.getLongExtra(VpnServiceImpl.EXTRA_LOG_EPOCH, -1)
            val logSequence = intent.getLongExtra(VpnServiceImpl.EXTRA_LOG_SEQUENCE, -1)
            runOnUiThread {
                if (logEpoch == diagnosticJournal.epoch && displayedLogEpoch != logEpoch) {
                    resetLogEpoch(logEpoch)
                }
                log?.let {
                    acceptLog(JournalRecord(DiagnosticLogStore.entry(it, logSessionId, logLevel, logTimeMs),
                        logEpoch, logSequence))
                }
                if (status == VpnServiceImpl.STATUS_STATS) {
                    updateSpeed(
                        intent.getLongExtra(VpnServiceImpl.EXTRA_UP, 0),
                        intent.getLongExtra(VpnServiceImpl.EXTRA_DOWN, 0)
                    )
                    updateStats(
                        intent.getLongExtra(VpnServiceImpl.EXTRA_UP_TOTAL, VpnServiceImpl.liveBytesUp),
                        intent.getLongExtra(VpnServiceImpl.EXTRA_DOWN_TOTAL, VpnServiceImpl.liveBytesDown)
                    )
                } else {
                    if (status == VpnServiceImpl.STATUS_CONNECTED) {
                        clientIp = intent.getStringExtra(VpnServiceImpl.EXTRA_IP) ?: ""
                        clientGateway = intent.getStringExtra(VpnServiceImpl.EXTRA_GATEWAY) ?: ""
                    }
                    updateUi(status, error)
                }
            }
        }
    }

    // Update check (opt-in; notification-only): checked once per app run, only while connected.
    private var updateChecked = false
    private var updateUrl: String? = null
    private var updateJob: Job? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)
        setDisconnectedState()
        val statePrefs = getSharedPreferences(PREFS_STATE, Context.MODE_PRIVATE)
        diagnosticJournal.setRetainLastError(statePrefs.getBoolean(PREF_RETAIN_ERROR_REPORT, false))
        diagnosticJournal.beginSession(currentDiagnosticSessionId())
        logTimeFormat = statePrefs
            .getString(PREF_LOG_TIME_FORMAT, DEFAULT_LOG_TIME_FORMAT)
            ?.trim()?.lowercase() ?: DEFAULT_LOG_TIME_FORMAT
        lastAutoProbeAtMs = statePrefs.getLong(PREF_LAST_AUTO_PROBE_MS, 0L)
        // After a theme switch / rotation the Activity is recreated but the VPN
        // foreground service keeps running — restore the real tunnel state so the
        // UI doesn't falsely show "Disconnected".
        restoreServiceState()
        if (connectRequest.isActive && !isConnected && !isDisconnecting && !isTrustedPaused) {
            setConnectingState()
        }

        loadProfiles()
        renderActiveProfile()
        renderProfileList()

        binding.tabs.addOnTabSelectedListener(object : TabLayout.OnTabSelectedListener {
            override fun onTabSelected(tab: TabLayout.Tab) { showTab(tab.position) }
            override fun onTabUnselected(tab: TabLayout.Tab) {}
            override fun onTabReselected(tab: TabLayout.Tab) {}
        })

        val filter = IntentFilter(VpnServiceImpl.BROADCAST_STATUS)
        // Not-exported on EVERY API level (via ContextCompat, like QeliTileService). The old
        // SDK>=33 gate left the receiver EXPORTED on API 26-32, where a co-installed app could
        // broadcast com.qeli.STATUS to spoof "Connected"/inject log lines — lethal for a
        // censorship tool (a user lured into sending cleartext while the UI claims protection).
        ContextCompat.registerReceiver(
            this, statusReceiver, filter, ContextCompat.RECEIVER_NOT_EXPORTED
        )
        restoreDiagnosticLog()

        binding.btnImport.setOnClickListener { showImportChooser() }
        binding.btnNewProfile.setOnClickListener { showEditor(-1) }
        binding.btnCheckAll.setOnClickListener { pingAll(manual = true) }
        binding.btnPing.setOnClickListener { pingActive(manual = true) }
        binding.ringConnect.setOnClickListener { onConnectTap(it) }

        // Log tab toolbar
        binding.btnLogClear.setOnClickListener {
            invalidatePendingReport()
            val completion = diagnosticJournal.clearAll()
            resetLogEpoch(diagnosticJournal.epoch)
            lifecycleScope.launch {
                try { completion.await() }
                catch (_: Exception) { Toast.makeText(this@MainActivity, R.string.report_clear_failed, Toast.LENGTH_LONG).show() }
            }
        }
        binding.btnLogCopy.setOnClickListener {
            (getSystemService(CLIPBOARD_SERVICE) as android.content.ClipboardManager)
                .setPrimaryClip(android.content.ClipData.newPlainText("qeli log", binding.tvLog.text))
            Toast.makeText(this, getString(R.string.log_copied), Toast.LENGTH_SHORT).show()
        }
        binding.btnLogReport.setOnClickListener { showDiagnosticExport() }
        binding.btnLogAutoscroll.setOnClickListener { setAutoScroll(!logAutoScroll) }
        setAutoScroll(true)

        // Theme toggle (light <-> dark), persisted; AppCompat recreates the activity.
        updateThemeIcon()
        binding.btnTheme.setOnClickListener { QeliApp.setDark(this, !QeliApp.isDark(this)) }
        binding.btnSettings.setOnClickListener { showSettingsDialog() }

        // Reuses the existing per-app picker rather than a second entry point for the same
        // setting; it edits the ACTIVE profile, which is what the card describes.
        binding.connectionInfoRow.setOnClickListener { showProtectionDetails() }

        binding.tvVersion.text = getString(R.string.version_label, appVersion())
        binding.tvVersion.setOnClickListener { showUpdatesDialog() }

        val prefs = statePrefs
        if (!prefs.getBoolean("battery_opt_requested", false)) {
            requestBatteryOptimizationExclusion(); prefs.edit().putBoolean("battery_opt_requested", true).apply()
        }
        // Launched by the Quick Settings tile? Connect the active profile now that the receiver
        // and UI are wired (so the connect flow's status/log updates land).
        maybeAutoConnect(intent)
        handleDeepLink(intent)   // opened via a tapped qeli:// link?
        // Auto-connect on launch (opt-in): only on a fresh cold start (not rotation/theme),
        // not already busy, and not already handling a tile / deep-link request.
        if (savedInstanceState == null && prefs.getBoolean(PREF_AUTO_CONNECT_LAUNCH, false)
            && !isConnected && !isConnecting && !isTrustedPaused
            && intent?.getBooleanExtra(EXTRA_AUTO_CONNECT, false) != true && intent?.data == null) {
            connect()
        }
    }

    override fun onStart() {
        super.onStart()
        uiVisible = true
        configureAutoProbeTimer(runImmediately = true)
    }

    override fun onStop() {
        uiVisible = false
        autoProbeJob?.cancel()
        autoProbeJob = null
        cancelAutomaticProbeJobs()
        super.onStop()
    }

    override fun onDestroy() {
        invalidatePendingReport()
        try { unregisterReceiver(statusReceiver) } catch (_: Exception) {}
        // Cancel the ring-spin animator: an INFINITE ObjectAnimator left running holds
        // a reference to binding.ringGradient (a view of this now-destroyed Activity),
        // leaking the whole Activity across recreation (rotation/theme switch while the
        // connect ring is spinning). cancel() detaches the animator from the target.
        ringSpin?.cancel(); ringSpin = null
        super.onDestroy()
    }

    private fun showTab(pos: Int) {
        binding.viewConnection.visibility = if (pos == 0) View.VISIBLE else View.GONE
        binding.viewProfiles.visibility = if (pos == 1) View.VISIBLE else View.GONE
        binding.viewLog.visibility = if (pos == 2) View.VISIBLE else View.GONE
        when (pos) {
            1 -> { renderProfileList(); pingAll(manual = false) }
            0 -> { renderActiveProfile(); pingActive(manual = false) }
        }
    }

    /** App version string for the diagnostics footer, e.g. "v0.7.5 (build 705)". */
    private fun appVersion(): String = try {
        val pi = packageManager.getPackageInfo(packageName, 0)
        val code = pi.longVersionCode
        "v${pi.versionName} (build $code)"
    } catch (_: Exception) { "v?" }

    /** Just the numeric versionName (e.g. "0.7.5") for comparison — distinct from the
     *  footer's "v0.7.5 (build 705)". */
    private fun rawVersionName(): String = try {
        packageManager.getPackageInfo(packageName, 0).versionName ?: "0"
    } catch (_: Exception) { "0" }

    /** Opt-in auto update check: once per session and only through a provably private tunnel. */
    private fun maybeCheckForUpdates() {
        if (!QeliApp.isCheckUpdates(this) || updateChecked) return
        val vpnNetwork = privateUpdateNetwork() ?: return
        updateChecked = true
        updateJob?.cancel()
        updateJob = lifecycleScope.launch {
            try {
                val info = UpdateChecker.check(rawVersionName(), vpnNetwork) ?: return@launch
                if (info.isNewer) showUpdateAvailable(info)
            } finally {
                // A reconnect cancels the blocking request before the physical path can leak.
                // The explicit Network may also fail before the status broadcast reaches us;
                // either case must let the next private generation retry.
                if (!isActive || privateUpdateNetwork() != vpnNetwork) updateChecked = false
            }
        }
    }

    private fun privateUpdateNetwork(): Network? {
        // The selected profile remains editable while its old config is still running.
        // Trust only the service-owned snapshot derived from that actual generation; parsing
        // current() here could turn a harmless editor change into an update request outside
        // the tunnel that is really active.
        if (!isConnected ||
            VpnServiceImpl.liveStatus != VpnServiceImpl.STATUS_CONNECTED ||
            !VpnServiceImpl.liveUpdatePrivatePath
        ) return null

        val manager = getSystemService(ConnectivityManager::class.java) ?: return null
        val vpnNetworks = runCatching {
            manager.allNetworks.filter { network ->
                manager.getNetworkCapabilities(network)?.let { capabilities ->
                    capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN) &&
                        capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                } == true
            }
        }.getOrDefault(emptyList())
        // Prefer the process default when it is the VPN. Some Android versions expose the
        // VpnService owner's carrier as its default even though an application socket can
        // still be explicitly bound to the sole VPN network; accept that unambiguous case.
        val active = runCatching { manager.activeNetwork }.getOrNull()
        return active?.takeIf { it in vpnNetworks }
            ?: vpnNetworks.singleOrNull()
    }


    /** Reveal an available update in the footer + a toast; the footer opens the dialog. */
    private fun showUpdateAvailable(info: UpdateInfo) {
        updateUrl = info.url
        binding.tvVersion.text = getString(R.string.version_update_available, appVersion())
        Toast.makeText(this, getString(R.string.update_available_toast, info.latest), Toast.LENGTH_LONG).show()
    }

    /** The app has no Settings screen — tapping the version footer opens this small dialog
     *  with the opt-in toggle and a manual "Check now". */
    private fun showUpdatesDialog() {
        val pad = (16 * resources.displayMetrics.density).toInt()
        val box = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(pad + pad, pad, pad + pad, 0)
        }
        val toggle = CheckBox(this).apply {
            text = getString(R.string.check_updates_auto)
            isChecked = QeliApp.isCheckUpdates(this@MainActivity)
            setOnCheckedChangeListener { _, on ->
                QeliApp.setCheckUpdates(this@MainActivity, on)
                if (on) {
                    maybeCheckForUpdates()
                } else {
                    // Revoking the opt-in also revokes an already-running request.
                    updateChecked = false
                    updateJob?.cancel()
                    updateJob = null
                }
            }
        }
        val status = TextView(this).apply {
            setPadding(0, pad, 0, 0)
            updateUrl?.let { u -> text = getString(R.string.update_tap_to_open); setOnClickListener { openUrl(u) } }
        }
        box.addView(toggle)
        box.addView(status)

        val dlg = MaterialAlertDialogBuilder(this)
            .setTitle(getString(R.string.version_label, appVersion()))
            .setView(box)
            .setNeutralButton(R.string.check_now, null)   // overridden below so it doesn't auto-dismiss
            .setPositiveButton(R.string.close, null)
            .create()
        dlg.show()
        dlg.getButton(android.app.AlertDialog.BUTTON_NEUTRAL).setOnClickListener {
            val vpnNetwork = privateUpdateNetwork()
            if (vpnNetwork == null) {
                status.text = getString(R.string.update_private_path_required)
                return@setOnClickListener
            }
            status.text = getString(R.string.update_checking)
            updateJob?.cancel()
            updateJob = lifecycleScope.launch {
                val info = UpdateChecker.check(rawVersionName(), vpnNetwork)
                when {
                    info == null -> status.text = getString(R.string.update_check_failed)
                    info.isNewer -> {
                        status.text = getString(R.string.update_available_open, info.latest)
                        status.setOnClickListener { openUrl(info.url) }
                        showUpdateAvailable(info)
                    }
                    else -> status.text = getString(R.string.update_latest)
                }
            }
        }
    }

    private fun openUrl(url: String) {
        try { startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url))) } catch (_: Exception) {}
    }

    /** Re-sync the UI to the running service's tunnel state (used after the
     *  Activity is recreated by a theme switch or rotation). */
    private fun restoreServiceState() {
        when (VpnServiceImpl.liveStatus) {
            VpnServiceImpl.STATUS_CONNECTED -> {
                clientIp = VpnServiceImpl.liveIp
                clientGateway = VpnServiceImpl.liveGateway
                setConnectedState()
            }
            VpnServiceImpl.STATUS_CONNECTING -> setConnectingState()
            VpnServiceImpl.STATUS_DISCONNECTING -> setDisconnectingState()
            VpnServiceImpl.STATUS_WAITING_TRUSTED -> setTrustedWaitingState()
            else -> { /* disconnected / error → already in the default state */ }
        }
    }

    /** Moon when light (tap → dark), sun when dark (tap → light). */
    private fun updateThemeIcon() {
        binding.btnTheme.setImageResource(if (QeliApp.isDark(this)) R.drawable.ic_sun else R.drawable.ic_moon)
    }

    private fun setAutoScroll(on: Boolean) {
        logAutoScroll = on
        // Short label so the ✓ state indicator stays visible even when the three
        // log-toolbar buttons share the width equally on narrow screens.
        binding.btnLogAutoscroll.text = getString(if (on) R.string.log_scroll_on else R.string.log_scroll_off)
        if (on) binding.scrollLog.post { binding.scrollLog.fullScroll(View.FOCUS_DOWN) }
    }

    // ── profiles ──────────────────────────────────────────────────────────--

    private fun current(): Profile? = profiles.getOrNull(activeIndex)

    /** Settings dialog: auto-connect toggles + profile backup/restore. */
    private fun showSettingsDialog() {
        val prefs = getSharedPreferences(PREFS_STATE, Context.MODE_PRIVATE)
        val d = resources.displayMetrics.density
        fun dp(v: Int) = (v * d).toInt()
        fun outlined() = com.google.android.material.button.MaterialButton(
            this, null, com.google.android.material.R.attr.materialButtonOutlinedStyle)
        val cbLaunch = android.widget.CheckBox(this).apply {
            text = getString(R.string.auto_connect_launch)
            isChecked = prefs.getBoolean(PREF_AUTO_CONNECT_LAUNCH, false)
        }
        val cbBoot = android.widget.CheckBox(this).apply {
            text = getString(R.string.auto_connect_boot)
            isChecked = prefs.getBoolean(PREF_AUTO_CONNECT_BOOT, false)
        }
        val cbLan = android.widget.CheckBox(this).apply {
            text = getString(R.string.allow_lan)
            isChecked = prefs.getBoolean(PREF_ALLOW_LAN, false)
        }
        val cbTrustedWifi = android.widget.CheckBox(this).apply {
            text = getString(R.string.trusted_wifi)
            isChecked = prefs.getBoolean(PREF_TRUSTED_WIFI_ENABLED, false)
        }
        val trustedWifiInput = com.google.android.material.textfield.TextInputEditText(this).apply {
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_MULTI_LINE
            minLines = 2
            maxLines = 5
            setText(prefs.getString(PREF_TRUSTED_WIFI_SSIDS, ""))
            isEnabled = cbTrustedWifi.isChecked
        }
        val trustedWifiField = com.google.android.material.textfield.TextInputLayout(
            this,
            null,
            com.google.android.material.R.attr.textInputOutlinedStyle,
        ).apply {
            hint = getString(R.string.trusted_wifi_ssids)
            helperText = getString(R.string.trusted_wifi_desc)
            isEnabled = cbTrustedWifi.isChecked
            addView(
                trustedWifiInput,
                android.widget.LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT,
                ),
            )
        }
        cbTrustedWifi.setOnCheckedChangeListener { _, enabled ->
            trustedWifiField.isEnabled = enabled
            trustedWifiInput.isEnabled = enabled
        }
        val cbAutoProbe = android.widget.CheckBox(this).apply {
            text = getString(R.string.auto_probe_profiles)
            isChecked = prefs.getBoolean(PREF_AUTO_PROBE, ProfileAutoProbePolicy.DEFAULT_ENABLED)
        }
        val probeIntervalInput = com.google.android.material.textfield.TextInputEditText(this).apply {
            inputType = InputType.TYPE_CLASS_NUMBER
            setText(
                ProfileAutoProbePolicy.clampIntervalSeconds(
                    prefs.getInt(
                        PREF_PROBE_INTERVAL_SECS,
                        ProfileAutoProbePolicy.DEFAULT_INTERVAL_SECS,
                    ),
                ).toString(),
            )
            setSelectAllOnFocus(true)
        }
        val probeIntervalField = com.google.android.material.textfield.TextInputLayout(
            this,
            null,
            com.google.android.material.R.attr.textInputOutlinedStyle,
        ).apply {
            hint = getString(R.string.probe_interval)
            suffixText = getString(R.string.seconds_short)
            isEnabled = cbAutoProbe.isChecked
            probeIntervalInput.isEnabled = cbAutoProbe.isChecked
            addView(
                probeIntervalInput,
                android.widget.LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT,
                ),
            )
        }
        val tvAutoProbe = android.widget.TextView(this).apply {
            text = getString(R.string.auto_probe_profiles_desc)
            textSize = 12f
            setTextColor(ContextCompat.getColor(context, R.color.text_secondary))
        }
        cbAutoProbe.setOnCheckedChangeListener { _, enabled ->
            probeIntervalField.isEnabled = enabled
            probeIntervalInput.isEnabled = enabled
        }
        // Interface language. Applied via AppCompatDelegate, which recreates this Activity —
        // so it is handled on Save and nothing else in the dialog needs to know about it.
        val langs = QeliApp.LANGUAGES
        val langLabels = listOf(R.string.language_en, R.string.language_ru)
        val tvLang = android.widget.TextView(this).apply {
            text = getString(R.string.language)
            setPadding(0, dp(8), 0, dp(4))
        }
        val currentLang = QeliApp.language(this)
        val rgLang = android.widget.RadioGroup(this)
        val langButtons = langs.indices.map { i ->
            android.widget.RadioButton(this).apply {
                id = View.generateViewId()
                text = getString(langLabels[i])
            }.also { rgLang.addView(it) }
        }
        rgLang.check(langButtons[langs.indexOf(currentLang).takeIf { it >= 0 } ?: 0].id)

        // Log timestamp shape — same value names as the server's [logging] time_format,
        // so a phone log and a server log can be compared line for line.
        val logFmts = listOf("time", "datetime", "rfc3339", "epoch", "none")
        val logFmtLabels = listOf(
            R.string.log_time_short, R.string.log_time_datetime,
            R.string.log_time_rfc3339, R.string.log_time_epoch, R.string.log_time_none,
        )
        val tvLogFmt = android.widget.TextView(this).apply {
            text = getString(R.string.log_time_format)
            setPadding(0, dp(8), 0, dp(4))
        }
        val current = prefs.getString(PREF_LOG_TIME_FORMAT, DEFAULT_LOG_TIME_FORMAT)
        val rgLogFmt = android.widget.RadioGroup(this)
        val logFmtButtons = logFmts.indices.map { i ->
            android.widget.RadioButton(this).apply {
                id = View.generateViewId()
                text = getString(logFmtLabels[i])
            }.also { rgLogFmt.addView(it) }
        }
        rgLogFmt.check(logFmtButtons[logFmts.indexOf(current).takeIf { it >= 0 } ?: 0].id)
        val logLevels = listOf("info", "debug")
        val logLevelLabels = listOf(R.string.log_compact, R.string.log_detailed)
        val tvLogLevel = android.widget.TextView(this).apply {
            text = getString(R.string.log_detail)
            setPadding(0, dp(8), 0, dp(4))
        }
        val currentLogLevel = prefs.getString(PREF_LOG_LEVEL, DEFAULT_LOG_LEVEL)
        val rgLogLevel = android.widget.RadioGroup(this)
        val logLevelButtons = logLevels.indices.map { i ->
            android.widget.RadioButton(this).apply {
                id = View.generateViewId()
                text = getString(logLevelLabels[i])
            }.also { rgLogLevel.addView(it) }
        }
        rgLogLevel.check(logLevelButtons[logLevels.indexOf(currentLogLevel).takeIf { it >= 0 } ?: 0].id)
        val cbClearLog = android.widget.CheckBox(this).apply {
            text = getString(R.string.clear_log_on_disconnect)
            isChecked = prefs.getBoolean(PREF_CLEAR_LOG_ON_DISCONNECT, DEFAULT_CLEAR_LOG_ON_DISCONNECT)
        }
        val tvClearLog = android.widget.TextView(this).apply {
            text = getString(R.string.clear_log_on_disconnect_desc)
            textSize = 12f
            setTextColor(ContextCompat.getColor(context, R.color.text_secondary))
        }
        val cbRetainReport = CheckBox(this).apply {
            text = getString(R.string.retain_error_report)
            isChecked = prefs.getBoolean(PREF_RETAIN_ERROR_REPORT, false)
        }
        val tvRetainReport = TextView(this).apply {
            text = getString(R.string.retain_error_report_desc)
            textSize = 12f
            setTextColor(ContextCompat.getColor(context, R.color.text_secondary))
        }
        val btnBackup = outlined().apply {
            text = getString(R.string.backup_profiles)
            setOnClickListener { backupLauncher.launch("qeli-profiles.json") }
        }
        val btnRestore = outlined().apply {
            text = getString(R.string.restore_profiles)
            setOnClickListener { restoreLauncher.launch(arrayOf("application/json", "text/plain", "*/*")) }
        }
        val box = android.widget.LinearLayout(this).apply {
            orientation = android.widget.LinearLayout.VERTICAL
            setPadding(dp(20), dp(12), dp(20), 0)
            addView(cbLaunch); addView(cbBoot); addView(cbLan); addView(cbTrustedWifi)
            addView(trustedWifiField, android.widget.LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply { marginStart = dp(26); topMargin = dp(4); bottomMargin = dp(8) })
            addView(cbAutoProbe)
            addView(probeIntervalField, android.widget.LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply { marginStart = dp(26); topMargin = dp(4) })
            addView(tvAutoProbe, android.widget.LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply { marginStart = dp(26); topMargin = dp(4); bottomMargin = dp(8) })
            addView(tvLang); addView(rgLang)
            addView(tvLogFmt); addView(rgLogFmt)
            addView(tvLogLevel); addView(rgLogLevel)
            addView(cbClearLog)
            addView(tvClearLog, android.widget.LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply { marginStart = dp(26); bottomMargin = dp(8) })
            addView(cbRetainReport)
            addView(tvRetainReport, android.widget.LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT,
            ).apply { marginStart = dp(26); bottomMargin = dp(8) })
            addView(android.widget.Space(context), android.widget.LinearLayout.LayoutParams(0, dp(12)))
            addView(btnBackup); addView(btnRestore)
        }
        // The log-format radios pushed this past one screen on short devices, and a
        // bare setView() does not scroll — the Save button went off-screen.
        val scroller = android.widget.ScrollView(this).apply { addView(box) }
        MaterialAlertDialogBuilder(this)
            .setTitle(R.string.settings)
            .setView(scroller)
            .setNegativeButton(R.string.cancel, null)
            .setPositiveButton(R.string.save) { _, _ ->
                val lanChanged = prefs.getBoolean(PREF_ALLOW_LAN, false) != cbLan.isChecked
                val pickedLogFmt = logFmts.getOrElse(
                    logFmtButtons.indexOfFirst { it.id == rgLogFmt.checkedRadioButtonId },
                ) { DEFAULT_LOG_TIME_FORMAT }
                val pickedLogLevel = logLevels.getOrElse(
                    logLevelButtons.indexOfFirst { it.id == rgLogLevel.checkedRadioButtonId },
                ) { DEFAULT_LOG_LEVEL }
                val probeInterval = ProfileAutoProbePolicy.clampIntervalSeconds(
                    probeIntervalInput.text?.toString()?.toIntOrNull()
                        ?: ProfileAutoProbePolicy.DEFAULT_INTERVAL_SECS,
                )
                val trustedSsids = TrustedWifiPolicy.serialize(
                    TrustedWifiPolicy.parse(trustedWifiInput.text?.toString()),
                )
                prefs.edit()
                    .putBoolean(PREF_AUTO_CONNECT_LAUNCH, cbLaunch.isChecked)
                    .putBoolean(PREF_AUTO_CONNECT_BOOT, cbBoot.isChecked)
                    .putBoolean(PREF_ALLOW_LAN, cbLan.isChecked)
                    .putBoolean(PREF_TRUSTED_WIFI_ENABLED, cbTrustedWifi.isChecked)
                    .putString(PREF_TRUSTED_WIFI_SSIDS, trustedSsids)
                    .putBoolean(PREF_AUTO_PROBE, cbAutoProbe.isChecked)
                    .putInt(PREF_PROBE_INTERVAL_SECS, probeInterval)
                    .putString(PREF_LOG_TIME_FORMAT, pickedLogFmt)
                    .putString(PREF_LOG_LEVEL, pickedLogLevel)
                    .putBoolean(PREF_CLEAR_LOG_ON_DISCONNECT, cbClearLog.isChecked)
                    .putBoolean(PREF_RETAIN_ERROR_REPORT, cbRetainReport.isChecked)
                    .apply()
                if (!cbRetainReport.isChecked) invalidatePendingReport()
                val reportPreference = diagnosticJournal.setRetainLastError(cbRetainReport.isChecked)
                lifecycleScope.launch {
                    try { reportPreference.await() }
                    catch (_: Exception) { Toast.makeText(this@MainActivity, R.string.report_clear_failed, Toast.LENGTH_LONG).show() }
                }
                if (cbTrustedWifi.isChecked && trustedSsids.isNotEmpty()) {
                    requestTrustedWifiPermissions()
                } else {
                    reevaluateTrustedWifi()
                }
                configureAutoProbeTimer(runImmediately = cbAutoProbe.isChecked)
                logTimeFormat = pickedLogFmt  // applies to the next line, no restart
                val pickedLang = langs.getOrElse(
                    langButtons.indexOfFirst { it.id == rgLang.checkedRadioButtonId },
                ) { QeliApp.DEFAULT_LANG }
                // Routing is fixed at establish(); a live tunnel must reconnect to pick up
                // the new LAN-bypass setting.
                if (lanChanged && (isConnected || isConnecting)) {
                    Toast.makeText(this, getString(R.string.reconnecting_lan), Toast.LENGTH_SHORT).show()
                    reconnectForSettings()
                }
                // Strictly last: recreate() tears down this Activity, so any work above that
                // still touches this window (the toast, connect()) has to have run already.
                if (pickedLang != QeliApp.language(this)) {
                    QeliApp.setLanguage(this, pickedLang)
                    recreate() // re-runs attachBaseContext → re-wraps with the new locale
                }
            }
            .show()
    }

    private fun requestTrustedWifiPermissions() {
        val required = buildList {
            add(Manifest.permission.ACCESS_COARSE_LOCATION)
            add(Manifest.permission.ACCESS_FINE_LOCATION)
            if (Build.VERSION.SDK_INT >= 33) add(Manifest.permission.NEARBY_WIFI_DEVICES)
        }.filter { permission ->
            ContextCompat.checkSelfPermission(this, permission) != PackageManager.PERMISSION_GRANTED
        }
        if (required.isEmpty()) reevaluateTrustedWifi()
        else trustedWifiPermissionLauncher.launch(required.toTypedArray())
    }

    /** Apply a settings edit to the already-running controller without creating a new service. */
    private fun reevaluateTrustedWifi() {
        if (VpnServiceImpl.liveStatus != VpnServiceImpl.STATUS_CONNECTED &&
            VpnServiceImpl.liveStatus != VpnServiceImpl.STATUS_CONNECTING &&
            VpnServiceImpl.liveStatus != VpnServiceImpl.STATUS_WAITING_TRUSTED) return
        runCatching {
            startService(Intent(this, VpnServiceImpl::class.java).apply {
                action = VpnServiceImpl.ACTION_REEVALUATE_TRUSTED
            })
        }
    }

    /** Export ALL profiles (the encrypted store's JSON blob) to a user-picked file. */
    private fun writeBackup(uri: android.net.Uri) {
        val blob = try { secureStore.getString(KEY_PROFILES, null) }
        catch (error: Exception) {
            Toast.makeText(this, getString(R.string.backup_failed, error.message ?: ""), Toast.LENGTH_LONG).show()
            return
        } ?: run { Toast.makeText(this, getString(R.string.nothing_to_back_up), Toast.LENGTH_SHORT).show(); return }
        // Optional passphrase: empty = legacy plaintext JSON; non-empty = AES-256-GCM
        // encrypted container so an exported file can't leak credentials at rest.
        promptPassphrase(getString(R.string.backup_passphrase_title), allowEmpty = true) { pass ->
            lifecycleScope.launch {
                try {
                    // KDF and a user-selected document provider can both block. Report success
                    // only after the entire write and close have completed off the UI thread.
                    withContext(Dispatchers.IO) {
                        BackupExporter.write(blob, pass) { contentResolver.openOutputStream(uri) }
                    }
                    val suffix = getString(if (pass.isEmpty()) R.string.backup_unencrypted else R.string.backup_encrypted)
                    Toast.makeText(this@MainActivity, getString(R.string.backed_up, profiles.size, suffix), Toast.LENGTH_SHORT).show()
                } catch (e: kotlinx.coroutines.CancellationException) {
                    throw e
                } catch (e: Exception) {
                    Toast.makeText(this@MainActivity, getString(R.string.backup_failed, e.message ?: ""), Toast.LENGTH_LONG).show()
                }
            }
        }
    }

    /** Restore ALL profiles from a backup file (replaces the current set, after confirmation).
     *  Transparently handles both the legacy plaintext JSON and a passphrase-encrypted export. */
    private fun readRestore(uri: android.net.Uri) {
        lifecycleScope.launch {
            try {
                val bytes = readUriBytesBounded(uri, MAX_IMPORTED_BACKUP_BYTES)
                if (com.qeli.crypto.BackupCrypto.isEncrypted(bytes)) {
                    promptPassphrase(getString(R.string.restore_passphrase_title), allowEmpty = false) { pass ->
                        if (pass.isEmpty()) {
                            bytes.fill(0)
                            Toast.makeText(
                                this@MainActivity,
                                getString(R.string.passphrase_required),
                                Toast.LENGTH_SHORT,
                            ).show()
                            return@promptPassphrase
                        }
                        // PBKDF2 is deliberately expensive. Keep even a normal 210k-round
                        // backup off the main thread; BackupCrypto also caps attacker-chosen
                        // iteration counts before entering the KDF.
                        lifecycleScope.launch {
                            val decrypted = try {
                                withContext(Dispatchers.Default) {
                                    com.qeli.crypto.BackupCrypto.decrypt(bytes, pass)
                                }
                            } catch (e: Exception) {
                                val message = if (e is javax.crypto.AEADBadTagException) {
                                    getString(R.string.wrong_passphrase)
                                } else {
                                    getString(R.string.restore_failed, e.message ?: "")
                                }
                                Toast.makeText(this@MainActivity, message, Toast.LENGTH_LONG).show()
                                return@launch
                            } finally {
                                bytes.fill(0)
                            }
                            try {
                                confirmAndRestore(decrypted)
                            } catch (e: Exception) {
                                Toast.makeText(
                                    this@MainActivity,
                                    getString(R.string.restore_failed, e.message ?: ""),
                                    Toast.LENGTH_LONG,
                                ).show()
                            }
                        }
                    }
                } else {
                    try {
                        require(bytes.size <= MAX_IMPORTED_FILE_BYTES) {
                            "plaintext backup exceeds 8 MiB"
                        }
                        confirmAndRestore(decodeUtf8Strict(bytes))
                    } finally {
                        bytes.fill(0)
                    }
                }
            } catch (e: Exception) {
                Toast.makeText(
                    this@MainActivity,
                    getString(R.string.restore_failed, e.message ?: ""),
                    Toast.LENGTH_LONG,
                ).show()
            }
        }
    }

    /** Read an untrusted document off the UI thread and reject it before memory use becomes
     * unbounded. The caller selects the plaintext-config or base64-expanded backup ceiling. */
    private suspend fun readUriBytesBounded(uri: Uri, maxBytes: Int): ByteArray =
        withContext(Dispatchers.IO) {
            val limit = if (maxBytes < 1024 * 1024) "${maxBytes / 1024} KiB"
                else "${maxBytes / (1024 * 1024)} MiB"
            contentResolver.openInputStream(uri)?.use { input ->
                BoundedInput.read(input, maxBytes, "file exceeds $limit import limit")
                    .also { require(it.isNotEmpty()) { "empty file" } }
            } ?: throw IllegalArgumentException("empty file")
        }

    /** Validate a decrypted/plaintext backup JSON, confirm, then replace the profile set. */
    private fun confirmAndRestore(text: String) {
        require(text.toByteArray(Charsets.UTF_8).size <= MAX_IMPORTED_FILE_BYTES) {
            "decrypted archive exceeds the supported size limit"
        }
        val root = JSONObject(text)                       // validate JSON
        val entries = root.optJSONArray("profiles")
            ?: throw IllegalArgumentException("not a Qeli backup: profiles must be an array")
        val n = entries.length()
        require(n in 1..MAX_IMPORTED_PROFILES) {
            "backup must contain 1..$MAX_IMPORTED_PROFILES profiles"
        }
        val candidate = ArrayList<Profile>(n)
        for (index in 0 until n) {
            val entry = entries.optJSONObject(index)
                ?: throw IllegalArgumentException("profile ${index + 1} must be an object")
            val name = entry.optString("name", "profile")
            val stored = storedProfileText(entry)
            validateProfileForStorage(name, stored, "profile ${index + 1}")
            try {
                VpnConfig.parse(stored)
            } catch (error: Exception) {
                throw IllegalArgumentException(
                    "profile ${index + 1} ('$name') is invalid: " +
                        (error.message ?: "invalid config"),
                    error,
                )
            }
            candidate.add(Profile(name, stored))
        }
        val restoredActive = ProfileStore.readActiveProfileIndex(root, n)
        MaterialAlertDialogBuilder(this)
            .setTitle(R.string.restore_profiles)
            .setMessage(getString(R.string.restore_confirm, n))
            .setNegativeButton(R.string.cancel, null)
            .setPositiveButton(R.string.restore_profiles) { _, _ ->
                // Restore is the explicit, confirmed replacement path for an unreadable store.
                try { persistCandidate(candidate, restoredActive, replacingUnreadableStore = true) }
                catch (error: Exception) {
                    Toast.makeText(this, getString(R.string.restore_failed, error.message ?: ""), Toast.LENGTH_LONG).show()
                    return@setPositiveButton
                }
                profiles.clear(); profiles.addAll(candidate); activeIndex = restoredActive
                reach.clear(); renderProfileList(); renderActiveProfile(); pingActive()
                Toast.makeText(this, getString(R.string.restored, n), Toast.LENGTH_SHORT).show()
            }
            .show()
    }

    /** Prompt for a backup passphrase. [allowEmpty]=true (export) lets the user skip encryption. */
    private fun promptPassphrase(title: String, allowEmpty: Boolean, onResult: (String) -> Unit) {
        val input = android.widget.EditText(this).apply {
            inputType = android.text.InputType.TYPE_CLASS_TEXT or
                android.text.InputType.TYPE_TEXT_VARIATION_PASSWORD
            hint = getString(
                if (allowEmpty) R.string.backup_passphrase_hint_optional
                else R.string.backup_passphrase_hint
            )
        }
        MaterialAlertDialogBuilder(this)
            .setTitle(title)
            .setView(input)
            .setNegativeButton(R.string.cancel, null)
            .setPositiveButton(android.R.string.ok) { _, _ -> onResult(input.text.toString()) }
            .show()
    }

    private fun loadProfiles() {
        profileStoreLoadRejected = false
        // Capture even an unreadable encrypted entry so explicit backup restore cannot
        // replace a newer entry written by another Activity while the dialog is open.
        val raw = try {
            observedProfileVersion = secureStore.version(KEY_PROFILES)
            secureStore.getString(KEY_PROFILES, null)
        } catch (error: Exception) {
            profileStoreLoadRejected = true
            Log.e("VpnMain", "profiles decrypt: ${error.message}")
            null
        }
        if (raw != null) {
            try {
                require(raw.toByteArray(Charsets.UTF_8).size <= MAX_IMPORTED_FILE_BYTES) {
                    "stored profile set exceeds the safety limit"
                }
                val root = JSONObject(raw)
                val arr = root.optJSONArray("profiles")
                    ?: throw IllegalArgumentException("stored profiles must be an array")
                require(arr.length() in 1..MAX_IMPORTED_PROFILES) {
                    "stored profile set must contain 1..$MAX_IMPORTED_PROFILES entries"
                }
                val storedActive = ProfileStore.readActiveProfileIndex(root, arr.length())
                val loaded = ArrayList<Profile>(arr.length())
                for (i in 0 until arr.length()) {
                    val p = arr.getJSONObject(i)
                    val name = p.optString("name", "profile")
                    val stored = storedProfileText(p)
                    validateProfileForStorage(name, stored, "profile ${i + 1}")
                    VpnConfig.parse(stored)
                    loaded.add(Profile(name, stored))
                }
                // Commit only after every entry parsed and validated. A corrupt tail must not
                // replace a previously usable in-memory set with a partial prefix.
                profiles.clear()
                profiles.addAll(loaded)
                activeIndex = storedActive
            } catch (e: Exception) {
                profileStoreLoadRejected = true
                Log.e("VpnMain", "profiles load: ${e.message}")
            }
        }
        if (profiles.isEmpty()) {
            profiles.add(Profile(getString(R.string.default_profile_name), TEMPLATE))
            // A rejected encrypted store must remain untouched until an explicit restore.
            if (!profileStoreLoadRejected) {
                try { persist() }
                catch (error: Exception) {
                    profileStoreLoadRejected = true
                    Log.e("VpnMain", "profiles initial save: ${error.message}")
                }
            }
        }
        if (profileStoreLoadRejected) {
            MaterialAlertDialogBuilder(this)
                .setTitle(R.string.profile_store_unavailable_title)
                .setMessage(R.string.profile_store_unavailable_message)
                .setPositiveButton(android.R.string.ok, null)
                .show()
        }
        if (activeIndex !in profiles.indices) activeIndex = 0
    }

    /** New backups store `cfg` (INI); very old field-based entries are normalized through the
     * current model. A retired `json` payload remains explicit input to `parse`, which rejects
     * it with the documented migration error instead of silently guessing. */
    private fun storedProfileText(profile: JSONObject): String =
        profile.optString("cfg", "").ifBlank {
            profile.optString("json", "").ifBlank { synthesizeIni(profile) }
        }.also { require(it.isNotBlank()) { "profile config is empty" } }

    /**
     * Legacy old-multi-profile entry (`{address,port,username}`) -> current flat-INI.
     *
     * Built through the model rather than by string concatenation so the key names come from
     * `toIni` and cannot drift from what `fromIni` reads. It used to be assembled as JSON and
     * handed to `VpnConfig.fromJson`; that parser has been removed, and
     * routing here was only ever the full-tunnel default anyway.
     *
     * A profile still stored under the older `json` key is NOT converted — it is passed through
     * as-is and `parse` reports the retired format by name, which is a legible instruction to
     * re-export rather than a second parser kept alive for one migration.
     */
    private fun synthesizeIni(p: JSONObject): String = try {
        VpnConfig(
            serverAddress = p.optString("address", ""),
            port = p.optInt("port", 443),
            username = p.optString("username", "phone"),
            // The old format never stored one; the user re-enters it. Empty, not a
            // placeholder — a placeholder would look like a saved credential.
            password = "",
        ).toIni()
    } catch (e: Exception) {
        // toIni validates; an entry too broken to render is left for parse to report.
        Log.e("VpnMain", "legacy profile migrate: ${e.message}")
        ""
    }

    private fun persistCandidate(
        items: List<Profile>,
        selectedIndex: Int,
        replacingUnreadableStore: Boolean = false,
    ) {
        check(!profileStoreLoadRejected || replacingUnreadableStore) {
            getString(R.string.profile_store_write_blocked)
        }
        val encoded = encodeProfileSet(items, selectedIndex)
        val expected = checkNotNull(observedProfileVersion) {
            "Load the profile store before saving."
        }
        val updated = try {
            secureStore.putStringIfVersion(
                KEY_PROFILES, expected, encoded,
                allowUnreadableLegacyRecovery = replacingUnreadableStore,
            )
        } catch (error: ProfileStore.SecureStore.StaleVersionException) {
            throw IllegalStateException(getString(R.string.profile_store_stale), error)
        }
        observedProfileVersion = updated
        profileStoreLoadRejected = false
        profileRevision++
    }

    private fun persist() = persistCandidate(profiles, activeIndex)

    /** Validate and encode a complete prospective state before mutating the live list. */
    private fun encodeProfileSet(items: List<Profile>, selectedIndex: Int): String {
        require(items.isNotEmpty()) { "profile set must not be empty" }
        require(items.size <= MAX_IMPORTED_PROFILES) {
            "profile limit ($MAX_IMPORTED_PROFILES) reached"
        }
        require(selectedIndex in items.indices) { "active profile index is out of range" }
        val arr = JSONArray()
        for ((index, p) in items.withIndex()) {
            validateProfileForStorage(p.name, p.text, "profile ${index + 1}")
            arr.put(JSONObject().put("name", p.name).put("cfg", p.text))
        }
        val encoded = JSONObject().put("active", selectedIndex).put("profiles", arr).toString()
        require(encoded.toByteArray(Charsets.UTF_8).size <= MAX_IMPORTED_FILE_BYTES) {
            "stored profile set exceeds the safety limit"
        }
        return encoded
    }

    private fun validateProfileForStorage(name: String, text: String, label: String = "profile") {
        require(name.isNotBlank()) { "$label name is empty" }
        require(name.length <= MAX_IMPORTED_PROFILE_NAME_CHARS) { "$label name is too long" }
        require(text.toByteArray(Charsets.UTF_8).size <= MAX_IMPORTED_CONFIG_BYTES) {
            "$label config exceeds the safety limit"
        }
    }

    /** Parsed address/port for display + ping; null on parse failure. */
    private fun endpointOf(p: Profile): Pair<String, Int>? = try {
        val c = VpnConfig.parse(p.text); Pair(c.serverAddress, c.port)
    } catch (_: Exception) { null }

    // ── editor dialog (text config) ──────────────────────────────────────--

    /** index = -1 to create a new profile. */
    private fun showEditor(index: Int) {
        val openedAtRevision = profileRevision
        val dlgBinding = DialogConfigEditorBinding.inflate(LayoutInflater.from(this))
        val editing = profiles.getOrNull(index)
        dlgBinding.editName.setText(editing?.name ?: getString(R.string.new_profile_title))
        val initialConfigText = editing?.text ?: TEMPLATE
        dlgBinding.editJson.setText(initialConfigText)
        val roamingPolicies = listOf("auto", "required", "off")
        val initialRoaming = runCatching { VpnConfig.parse(initialConfigText).roaming }.getOrDefault("auto")
        dlgBinding.spinnerRoaming.setSelection(roamingPolicies.indexOf(initialRoaming).coerceAtLeast(0))

        val dialog = MaterialAlertDialogBuilder(this)
            .setTitle(getString(if (index < 0) R.string.new_profile_title else R.string.edit_profile_title))
            .setView(dlgBinding.root)
            .setNegativeButton(R.string.cancel, null)
            .setPositiveButton(R.string.save, null)   // override below to validate
            .create()
        dialog.show()
        dialog.getButton(android.app.AlertDialog.BUTTON_POSITIVE).setOnClickListener {
            val cfgText = dlgBinding.editJson.text.toString()
            val roamingPolicy = roamingPolicies.getOrElse(dlgBinding.spinnerRoaming.selectedItemPosition) { "auto" }
            val cfg = try {
                VpnConfig.parse(cfgText).copy(roaming = roamingPolicy).also { it.validate() }
            } catch (e: Exception) {
                Toast.makeText(this, getString(R.string.invalid_config, e.message ?: ""), Toast.LENGTH_LONG).show(); return@setOnClickListener
            }
            // The form owns roaming; canonical INI keeps every modelled/carried portable key.
            val iniText = cfg.toIni()
            var name = dlgBinding.editName.text.toString().trim()
            if (name.isBlank()) name = cfg.serverAddress.ifBlank { getString(R.string.profile_fallback_name) }
            if (profileRevision != openedAtRevision) {
                Toast.makeText(this, R.string.profile_changed_during_edit, Toast.LENGTH_LONG).show()
                return@setOnClickListener
            }
            val reconnectNeeded = editing != null && index == activeIndex &&
                editing.text != iniText && (isConnected || isConnecting || isTrustedPaused)
            val candidate = profiles.map { it.copy() }.toMutableList()
            if (index < 0) candidate.add(Profile(name, iniText))
            else candidate[index] = Profile(name, iniText)
            val candidateActive = if (index < 0) activeAfterAdd(candidate.size) else activeIndex
            try {
                persistCandidate(candidate, candidateActive)
            } catch (e: Exception) {
                Toast.makeText(this, e.message ?: getString(R.string.invalid_config, ""), Toast.LENGTH_LONG).show()
                return@setOnClickListener
            }
            profiles.clear(); profiles.addAll(candidate); activeIndex = candidateActive
            renderProfileList(); renderActiveProfile(); pingActive()
            dialog.dismiss()
            if (reconnectNeeded) {
                Toast.makeText(this, R.string.profile_reconnect_required, Toast.LENGTH_LONG).show()
            }
        }
    }

    /** Offer the three ways to add a profile: file, QR scan, or pasted link. */
    private fun showImportChooser() {
        val options = arrayOf(getString(R.string.add_scan_qr), getString(R.string.add_paste_link),
            getString(R.string.add_import_file))
        MaterialAlertDialogBuilder(this)
            .setTitle(R.string.add_profile_title)
            .setItems(options) { _, which ->
                when (which) {
                    0 -> startQrScan()
                    1 -> showPasteLinkDialog()
                    2 -> try { importConfigLauncher.launch(arrayOf("text/plain", "*/*")) }
                         catch (e: Exception) { Toast.makeText(this, getString(R.string.cannot_open_picker, e.message ?: ""), Toast.LENGTH_LONG).show() }
                }
            }
            .show()
    }

    private fun startQrScan() {
        val opts = ScanOptions()
            .setDesiredBarcodeFormats(ScanOptions.QR_CODE)
            .setPrompt(getString(R.string.scan_qr_prompt))
            .setBeepEnabled(false)
            .setOrientationLocked(false)
            .setCaptureActivity(QrCaptureActivity::class.java)
        qrScanLauncher.launch(opts)
    }

    private fun showPasteLinkDialog() {
        val input = EditText(this).apply { hint = getString(R.string.paste_link_hint); setSingleLine(false) }
        MaterialAlertDialogBuilder(this)
            .setTitle(R.string.paste_link_title)
            .setView(input)
            .setNegativeButton(R.string.cancel, null)
            .setPositiveButton(R.string.save) { _, _ -> addProfileFromQeliUri(input.text.toString()) }
            .show()
    }

    /** Parse a scanned/pasted qeli:// link and add it as a profile (stored as INI). */
    private fun addProfileFromQeliUri(raw: String) {
        try {
            val cfg = VpnConfig.fromQeliUri(raw).also { it.validate() }
            val label = cfg.carriedKeys["name"]?.takeIf { it.isNotBlank() } ?: cfg.serverAddress
            val ini = cfg.toIni(label)
            val candidate = profiles.map { it.copy() }.toMutableList()
            candidate.add(Profile(label, ini))
            val candidateActive = activeAfterAdd(candidate.size)
            persistCandidate(candidate, candidateActive)
            profiles.clear(); profiles.addAll(candidate); activeIndex = candidateActive
            renderProfileList(); renderActiveProfile(); pingActive()
            binding.tabs.getTabAt(0)?.select()
            appendLog("Imported \"$label\" from QR/link")
            Toast.makeText(
                this@MainActivity,
                getString(R.string.imported_toast, label),
                Toast.LENGTH_SHORT,
            ).show()
        } catch (e: Exception) {
            Toast.makeText(this, getString(R.string.invalid_link, e.message ?: ""), Toast.LENGTH_LONG).show()
        }
    }

    /** Extract the human label from a qeli:// fragment (#label), if present. */
    private fun qeliLabel(uri: String): String? = runCatching {
        VpnConfig.fromQeliUri(uri).carriedKeys["name"]?.takeIf { it.isNotBlank() }
    }.getOrNull()

    private fun importConfigFromUri(uri: Uri) {
        lifecycleScope.launch {
            try {
                val bytes = readUriBytesBounded(uri, MAX_IMPORTED_CONFIG_BYTES)
                // Decode strictly: replacement characters could silently alter credentials.
                // Preserve the INI tail so the shared parser can reject malformed controls.
                val text = try { bytes.decodeToString(throwOnInvalidSequence = true) } finally { bytes.fill(0) }
                require(text.isNotBlank()) { "Empty file" }
                val content = text.trimStart(' ', '\t', '\r', '\n', '\uFEFF')
                // A file may hold a qeli:// link or an INI config. JSON config is refused
                // by the shared parser; JSON backup files use the separate Restore action.
                if (content.startsWith("qeli://")) {
                    addProfileFromQeliUri(text)
                    return@launch
                }
                // Strict parsing validates untrusted INI at the import boundary.
                val cfg = VpnConfig.parse(text)
                // Stored verbatim: what parsed is already INI, so re-emitting it through `toIni`
                // would only drop the author's comments and ordering for no gain.
                val label = commentLabel(content).orEmpty().ifBlank { cfg.serverAddress }
                val candidate = profiles.map { it.copy() }.toMutableList()
                candidate.add(Profile(label, text))
                val candidateActive = activeAfterAdd(candidate.size)
                persistCandidate(candidate, candidateActive)
                profiles.clear(); profiles.addAll(candidate); activeIndex = candidateActive
                renderProfileList(); renderActiveProfile(); pingActive()
                binding.tabs.getTabAt(0)?.select()
                appendLog("Imported \"$label\"")
                Toast.makeText(
                    this@MainActivity,
                    getString(R.string.imported_toast, label),
                    Toast.LENGTH_SHORT,
                ).show()
            } catch (e: Exception) {
                Toast.makeText(
                    this@MainActivity,
                    getString(R.string.invalid_config, e.message ?: ""),
                    Toast.LENGTH_LONG,
                ).show()
            }
        }
    }

    /** Leading `# label` comment line of an INI config, if present. */
    private fun commentLabel(text: String): String? =
        text.lineSequence().firstOrNull()?.trim()?.takeIf { it.startsWith("#") }?.removePrefix("#")?.trim()?.ifBlank { null }

    // ── rendering ────────────────────────────────────────────────────────--

    private fun renderActiveProfile() {
        val p = current()
        binding.tvActiveProfile.text = p?.name ?: "—"
        val ms = reach[activeIndex]
        applyReach(binding.activeReachDot, binding.tvActiveReach, p, ms)
        renderConnectionInfo()
    }

    /**
     * The full picture behind the protection card.
     *
     * Values negotiated with the server (DNS, MTU, bonded streams, pushed routes) and the
     * system lockdown state are only known while a tunnel is up, so they are shown from the
     * service snapshot and simply omitted when disconnected — never guessed from the
     * profile, and never scraped out of the log.
     */
    private fun showProtectionDetails() {
        val properties = VpnServiceImpl.liveConnectionProperties ?: return
        val s = properties.protection
        val live = isConnected
        val rows = mutableListOf<Pair<Int, String>>()
        rows += R.string.detail_server to properties.displayEndpoint
        rows += R.string.detail_transport to
            "${properties.wireMode} / ${properties.protocol.uppercase()}" +
                (if (properties.quicEnabled) " + QUIC" else "")
        rows += R.string.detail_crypto to
            getString(if (s.postQuantum) R.string.protection_pq else R.string.protection_classic)
        rows += R.string.detail_server_key to
            getString(if (s.keyPinned) R.string.protection_key_pinned else R.string.protection_key_tofu)
        // The compact strip intentionally has room for one highest-priority warning. The
        // detail sheet is the promised full picture, so list every independent carve-out
        // instead of silently hiding the second and later warnings.
        for (warning in s.warnings) {
            rows += R.string.detail_warning to protectionWarningText(
                warning, s.excludedRouteCount
            )
        }
        if (live) {
            val pushed = VpnServiceImpl.livePushed
            pushed.familyMode?.let { family ->
                rows += R.string.detail_ip_family to getString(when (family) {
                    "ipv4" -> R.string.detail_ipv4
                    "ipv6" -> R.string.detail_ipv6
                    else -> R.string.detail_dual_stack
                })
            }
            pushed.carrierAddress?.let { address ->
                val endpoint = if (address.contains(':')) "[$address]:${properties.port}"
                else "$address:${properties.port}"
                rows += R.string.detail_carrier to endpoint
            }
            rows += R.string.detail_tunnel_ip to VpnServiceImpl.liveAddresses.ifEmpty { VpnServiceImpl.liveIp }
            // `liveDns` is the resolver the tunnel ACTUALLY programmed, and empty is a real
            // answer: it means none was installed and the device keeps its own.
            //
            // Falling back to the profile's `dns` list here undid the fix that produced that
            // value. The empty case is precisely `dns = off` / `dns = system`, where the
            // profile's resolvers are deliberately NOT applied — so the row named servers the
            // tunnel had ignored, which is the claim the whole card exists not to make. The
            // profile is not a fallback for a live fact; while connected there is only one
            // right answer and the service already computed it.
            // (Audit 2026-08-02, follow-up.)
            rows += R.string.detail_dns to VpnServiceImpl.liveDns.ifEmpty {
                getString(R.string.protection_dns_system)
            }
            if (VpnServiceImpl.liveMtu > 0) {
                rows += R.string.detail_mtu to
                    "${VpnServiceImpl.liveMtu}${if (properties.configuredMtu > 0) "" else " (auto)"}"
            }
            pushed.recordizerMode?.let { mode ->
                val displayMode = when (mode) {
                    "packet_mux_v1" -> "PACKET_MUX_V1"
                    else -> getString(R.string.detail_legacy_packet_record)
                }
                rows += R.string.detail_recordizer to negotiatedModeText(
                    displayMode, pushed.recordizerPolicy)
            }
            pushed.roamingMode?.let { mode ->
                val displayMode = when (mode) {
                    "udp_roam_v1" -> "UDP_ROAM_V1"
                    "tcp_resume_v2" -> "TCP_RESUME_V2"
                    "tcp_handover_v2" -> "TCP_HANDOVER_V2 + TCP_RESUME_V2"
                    else -> getString(R.string.detail_reconnect_fallback)
                }
                rows += R.string.detail_roaming to negotiatedModeText(
                    displayMode, pushed.roamingPolicy)
            }
            if (VpnServiceImpl.liveStreams > 1) {
                rows += R.string.detail_multipath to (
                    getString(R.string.detail_streams, VpnServiceImpl.liveStreams) +
                        if (pushed.multipathAdaptive) ", " + getString(R.string.detail_adaptive) else ""
                    )
            }
            // Only a sample is ever held or shown: a server may advertise a very long list,
            // and this dialog inflates one view per row with no recycling. The count is the
            // honest part; the sample is there to make it concrete.
            if (pushed.routeCount > 0) {
                val shown = pushed.routes.joinToString(", ")
                val extra = pushed.routeCount - pushed.routes.size
                val line =
                    if (extra > 0) getString(R.string.detail_routes_more, shown, extra)
                    else "$shown (${pushed.routeCount})"
                // The count above is what the SERVER SENT. When fewer actually went into the
                // builder, say so on the same row: the card is read as a statement about the
                // device, and a route that failed to install is traffic outside the tunnel —
                // exactly the direction in which this card must never be optimistic.
                rows += R.string.detail_pushed_routes to
                    if (pushed.routesInstalled in 0 until pushed.routeCount)
                        getString(
                            R.string.detail_routes_partial, line, pushed.routesInstalled,
                            pushed.routeCount
                        )
                    else line
            }
            // The DPI-resistance knobs actually in force, which the server owns.
            rows += R.string.detail_padding to
                if (pushed.paddingEnabled) "${pushed.paddingMin}–${pushed.paddingMax} B"
                else getString(R.string.detail_off)
            rows += R.string.detail_heartbeat to
                if (pushed.heartbeatEnabled) "${pushed.heartbeatIntervalMs / 1000} s"
                else getString(R.string.detail_off)
            rows += R.string.detail_shaping to getString(
                if (pushed.shapingEnabled) R.string.detail_on else R.string.detail_off
            )
            rows += R.string.detail_lockdown to getString(
                if (VpnServiceImpl.liveLockdown) R.string.detail_on else R.string.detail_off
            )
        }
        rows += R.string.detail_routing to when (s.scope) {
            ProtectionScope.ALL -> getString(R.string.per_app_all)
            ProtectionScope.ONLY_SELECTED -> getString(R.string.protection_selected_apps, s.appCount)
            ProtectionScope.ALL_EXCEPT -> getString(R.string.protection_except_apps, s.appCount)
            ProtectionScope.SPLIT_ROUTES -> getString(R.string.protection_split)
        }
        rows += R.string.detail_reconnect to getString(
            if (properties.reconnectEnabled) R.string.detail_on else R.string.detail_off
        )

        val d = resources.displayMetrics.density
        fun dp(v: Int) = (v * d).toInt()
        val box = android.widget.LinearLayout(this).apply {
            orientation = android.widget.LinearLayout.VERTICAL
            setPadding(dp(20), dp(8), dp(20), 0)
        }
        for ((labelRes, value) in rows) {
            box.addView(android.widget.LinearLayout(this).apply {
                orientation = android.widget.LinearLayout.HORIZONTAL
                setPadding(0, dp(5), 0, dp(5))
                addView(android.widget.TextView(this@MainActivity).apply {
                    text = getString(labelRes)
                    setTextColor(getColor(R.color.text_secondary))
                    textSize = 13f
                    layoutParams = android.widget.LinearLayout.LayoutParams(0, -2, 1f)
                })
                addView(android.widget.TextView(this@MainActivity).apply {
                    text = value
                    setTextColor(getColor(R.color.text_primary))
                    textSize = 13f
                })
            })
        }
        // The two actions live here rather than on the card: both merely navigate (the
        // existing per-app picker, and the system VPN screen), and on the card they cost
        // 60dp — enough to push the connection tab into a scroll once a tunnel is up.
        fun outlined() = com.google.android.material.button.MaterialButton(
            this, null, com.google.android.material.R.attr.materialButtonOutlinedStyle)
        val actions = android.widget.LinearLayout(this).apply {
            orientation = android.widget.LinearLayout.HORIZONTAL
            setPadding(0, dp(14), 0, 0)
        }
        val lp = android.widget.LinearLayout.LayoutParams(0, -2, 1f)
        actions.addView(outlined().apply {
            text = getString(R.string.protection_apps)
            layoutParams = android.widget.LinearLayout.LayoutParams(lp).also { it.marginEnd = dp(6) }
            setOnClickListener { showAppsDialog(activeIndex) }
        })
        actions.addView(outlined().apply {
            text = getString(R.string.protection_always_on)
            layoutParams = android.widget.LinearLayout.LayoutParams(lp).also { it.marginStart = dp(6) }
            // Always-on + "block connections without VPN" is a SYSTEM setting a regular VPN
            // app cannot flip, so this action opens the authoritative Android screen.
            setOnClickListener {
                try { startActivity(Intent(Settings.ACTION_VPN_SETTINGS)) }
                catch (e: Exception) { Toast.makeText(this@MainActivity, e.message ?: "", Toast.LENGTH_SHORT).show() }
            }
        })
        box.addView(actions)

        MaterialAlertDialogBuilder(this)
            .setTitle(R.string.connection_properties)
            .setView(android.widget.ScrollView(this).apply { addView(box) })
            .setPositiveButton(R.string.close, null)
            .show()
    }

    private fun protectionWarningText(warning: ProtectionWarning, excludedRouteCount: Int): String =
        when (warning) {
            ProtectionWarning.LAN_OUTSIDE -> getString(R.string.protection_warn_lan)
            ProtectionWarning.IPV4_OUTSIDE -> getString(R.string.protection_warn_ipv4)
            ProtectionWarning.IPV6_OUTSIDE -> getString(R.string.protection_warn_ipv6)
            ProtectionWarning.EXCLUDED_ROUTES ->
                getString(R.string.protection_warn_excluded, excludedRouteCount)
            ProtectionWarning.NO_PINNED_KEY -> getString(R.string.protection_warn_no_key)
        }

    private fun negotiatedModeText(mode: String, policy: String?): String =
        if (policy.isNullOrBlank()) mode
        else getString(R.string.detail_mode_policy, mode, policy)

    /**
     * Fill the one-line connection-info strip from the live generation snapshot.
     *
     * This deliberately does NOT render a verdict. The card it replaced led with a bold
     * "All traffic is protected", which is the strongest claim in the app and the easiest to
     * get subtly wrong; the strip states the facts instead — mode, transport, key exchange,
     * how the peer is trusted — and lets the detail sheet carry the rest.
     *
     * When something narrows the tunnel, the whole strip turns amber and shows THAT instead
     * of the facts: a carve-out is what the user needs to see first, and there is only one
     * line to say it in. [ProtectionSummary] still decides; the service calculated it from
     * the immutable connected config and the app-wide LAN toggle when the TUN was applied.
     */
    private fun renderConnectionInfo() {
        val properties = VpnServiceImpl.liveConnectionProperties
        val row = binding.connectionInfoRow
        val text = binding.tvConnectionInfo
        // Properties OF A CONNECTION — so there is nothing to state until there is one. This
        // also gives the idle screen the whole card's height back, which is where the tab was
        // tightest.
        if (!isConnected || properties == null) {
            row.visibility = View.GONE
            return
        }
        row.visibility = View.VISIBLE
        row.isClickable = true

        val s = properties.protection
        val warning = s.warnings.firstOrNull()?.let {
            protectionWarningText(it, s.excludedRouteCount)
        }
        if (warning != null) {
            text.text = warning
            text.setTextColor(getColor(R.color.status_connecting))
            return
        }
        // `mode · TRANSPORT[/QUIC] · key exchange · how the peer is trusted`
        text.text = listOf(
            properties.wireMode,
            properties.protocol.uppercase() + if (properties.quicEnabled) " / QUIC" else "",
            getString(if (s.postQuantum) R.string.protection_pq_short else R.string.protection_classic_short),
            getString(if (s.keyPinned) R.string.protection_key_pinned else R.string.protection_key_tofu),
        ).joinToString(" · ")
        text.setTextColor(getColor(R.color.text_secondary))
    }

    private fun renderProfileList() {
        val list = binding.profileList
        list.removeAllViews()
        binding.tvNoProfiles.visibility = if (profiles.isEmpty()) View.VISIBLE else View.GONE
        profiles.forEachIndexed { i, p ->
            val row = ItemProfileBinding.inflate(layoutInflater, list, false)
            row.root.background = ContextCompat.getDrawable(this, if (i == activeIndex) R.drawable.bg_row_active else R.drawable.bg_row)
            row.rowName.text = p.name
            val ep = endpointOf(p)
            row.rowSub.text = if (ep != null) "${ep.first}:${ep.second}" else getString(R.string.invalid_config_row)
            applyReach(row.rowReachDot, null, p, reach[i])
            // Compact latency next to the dot: "42 ms" reachable · "…" checking · "" unknown/down.
            row.rowReachMs.text = reach[i].let { ms ->
                when { ms == null -> ""; ms == -2L -> "…"; ms < 0 -> ""; else -> getString(R.string.latency_ms, ms) }
            }
            // Switching the active profile is refused while a tunnel is up — it would tear
            // down a live connection on a single tap. Dim the other rows so it reads as
            // unavailable before the tap, but keep them clickable so the tap can explain why.
            val locked = (isConnected || isConnecting || isDisconnecting || isTrustedPaused) && i != activeIndex
            row.root.alpha = if (locked) 0.45f else 1f
            row.root.setOnClickListener {
                if (locked) {
                    Toast.makeText(this, getString(R.string.switch_blocked), Toast.LENGTH_SHORT).show()
                    return@setOnClickListener
                }
                try { persistCandidate(profiles, i) }
                catch (e: Exception) {
                    Toast.makeText(this, e.message ?: "Could not save profile", Toast.LENGTH_LONG).show()
                    return@setOnClickListener
                }
                activeIndex = i; renderProfileList(); renderActiveProfile()
                binding.tabs.getTabAt(0)?.select()
                Toast.makeText(this, getString(R.string.active_profile_toast, p.name), Toast.LENGTH_SHORT).show()
            }
            // The row menu (edit / duplicate / share / delete) stays fully enabled: managing
            // OTHER profiles is unrelated to which one the tunnel is running.
            row.rowMenu.setOnClickListener { showRowMenu(it, i) }
            list.addView(row.root)
        }
    }

    private fun applyReach(dot: View, label: android.widget.TextView?, p: Profile?, ms: Long?) {
        val color = when {
            ms == null -> R.color.text_hint
            ms == -2L -> R.color.status_connecting
            ms < 0 -> R.color.status_error
            else -> R.color.status_connected
        }
        dot.backgroundTintList = android.content.res.ColorStateList.valueOf(getColor(color))
        label?.text = when {
            ms == null -> getString(R.string.reach_tap_ping)
            ms == -2L -> getString(R.string.reach_checking)
            ms < 0 -> getString(R.string.reach_unreachable)
            else -> getString(R.string.reach_ok, ms)
        }
    }

    /** Overflow (⋮) menu for a profile row: Share / Edit / Duplicate / Apps / Move / Delete. */
    private fun showRowMenu(anchor: View, i: Int) {
        val openedAtRevision = profileRevision
        val openedProfile = profiles.getOrNull(i) ?: return
        val menu = android.widget.PopupMenu(this, anchor)
        menu.menu.add(0, 1, 0, R.string.share_profile)
        menu.menu.add(0, 2, 1, R.string.edit_profile)
        menu.menu.add(0, 3, 2, R.string.duplicate_profile)
        menu.menu.add(0, 7, 3, R.string.per_app_title)
        menu.menu.add(0, 4, 4, R.string.move_up).isEnabled = i > 0
        menu.menu.add(0, 5, 5, R.string.move_down).isEnabled = i < profiles.size - 1
        menu.menu.add(0, 6, 6, R.string.delete_profile)
        menu.setOnMenuItemClickListener { item ->
            if (profileRevision != openedAtRevision || profiles.getOrNull(i) !== openedProfile) {
                Toast.makeText(this, R.string.profile_changed_during_edit, Toast.LENGTH_LONG).show()
                return@setOnMenuItemClickListener true
            }
            when (item.itemId) {
                1 -> { shareProfile(i); true }
                2 -> { showEditor(i); true }
                3 -> { duplicateProfile(i); true }
                7 -> { showAppsDialog(i); true }
                4 -> { moveProfile(i, -1); true }
                5 -> { moveProfile(i, 1); true }
                6 -> { deleteProfile(i); true }
                else -> false
            }
        }
        menu.show()
    }

    /**
     * Per-app split tunnel picker for a profile. Lets the user choose a routing mode
     * (all / only-selected / all-except-selected) and tick the apps it applies to. The
     * choice is stored back into the profile's INI (`apps_mode` + `apps` keys) so it
     * travels with backup/share and is applied by [QeliService] at establish().
     */
    private fun showAppsDialog(i: Int) {
        val profile = profiles.getOrNull(i) ?: return
        val openedAtRevision = profileRevision
        val cfg = try { VpnConfig.parse(profile.text) } catch (_: Exception) { null }
        val startMode = cfg?.appsMode ?: "all"
        val startSel = cfg?.apps?.toHashSet() ?: hashSetOf()

        val d = resources.displayMetrics.density
        fun dp(v: Int) = (v * d).toInt()

        // Mode radios.
        val rgMode = android.widget.RadioGroup(this)
        val rbAll = android.widget.RadioButton(this).apply { id = View.generateViewId(); text = getString(R.string.per_app_all) }
        val rbInc = android.widget.RadioButton(this).apply { id = View.generateViewId(); text = getString(R.string.per_app_include) }
        val rbExc = android.widget.RadioButton(this).apply { id = View.generateViewId(); text = getString(R.string.per_app_exclude) }
        rgMode.addView(rbAll); rgMode.addView(rbInc); rgMode.addView(rbExc)
        rgMode.check(when (startMode) { "include" -> rbInc.id; "exclude" -> rbExc.id; else -> rbAll.id })

        // App list container (populated off the main thread — enumerating packages is slow).
        val listBox = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        val loading = TextView(this).apply { text = getString(R.string.loading_apps); setPadding(0, dp(8), 0, dp(8)) }
        listBox.addView(loading)
        val checks = HashMap<String, CheckBox>()
        var appsLoaded = false

        fun setListEnabled(on: Boolean) { for (c in checks.values) c.isEnabled = on }

        val scroll = android.widget.ScrollView(this).apply {
            layoutParams = LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, dp(320))
            addView(listBox)
        }
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(20), dp(8), dp(20), 0)
            addView(rgMode); addView(scroll)
        }

        rgMode.setOnCheckedChangeListener { _, id -> setListEnabled(id != rbAll.id) }

        val dialog = MaterialAlertDialogBuilder(this)
            .setTitle(R.string.per_app_title)
            .setView(root)
            .setNegativeButton(R.string.cancel, null)
            .setPositiveButton(R.string.save) { _, _ ->
                if (!appsLoaded) return@setPositiveButton
                if (profileRevision != openedAtRevision) {
                    Toast.makeText(this, R.string.profile_changed_during_edit, Toast.LENGTH_LONG).show()
                    return@setPositiveButton
                }
                val mode = when (rgMode.checkedRadioButtonId) { rbInc.id -> "include"; rbExc.id -> "exclude"; else -> "all" }
                val sel = checks.filterValues { it.isChecked }.keys.sorted()
                val candidate = profiles.map { it.copy() }.toMutableList()
                val reconnectNeeded: Boolean
                try {
                    candidate[i].text = ProfileAppsEditor.replace(profile.text, mode, sel)
                    reconnectNeeded = i == activeIndex && candidate[i].text != profile.text &&
                        (isConnected || isConnecting || isTrustedPaused)
                    VpnConfig.parse(candidate[i].text)
                    persistCandidate(candidate, activeIndex)
                } catch (e: Exception) {
                    Toast.makeText(this, e.message ?: "Invalid per-app profile", Toast.LENGTH_LONG).show()
                    return@setPositiveButton
                }
                profiles.clear(); profiles.addAll(candidate)
                val n = if (mode == "all") 0 else sel.size
                Toast.makeText(this, if (mode == "all") getString(R.string.per_app_all_toast) else getString(R.string.per_app_selected_toast, n), Toast.LENGTH_SHORT).show()
                if (reconnectNeeded) {
                    Toast.makeText(this, R.string.profile_reconnect_required, Toast.LENGTH_LONG).show()
                }
            }
            .create()
        dialog.show()
        dialog.getButton(androidx.appcompat.app.AlertDialog.BUTTON_POSITIVE).isEnabled = false

        // Preserve configured packages that are uninstalled/hidden from this inventory.
        // A round trip through this editor must not silently broaden a per-app profile.
        val enumeration = lifecycleScope.launch {
            val apps = withContext(Dispatchers.IO) {
                val known = loadSelectableApps().associateBy { it.pkg }.toMutableMap()
                for (pkg in startSel) known.putIfAbsent(pkg, AppEntry(pkg, pkg))
                known.values.sortedBy { it.label.lowercase() }
            }
            if (!dialog.isShowing) return@launch
            listBox.removeView(loading)
            for (app in apps) {
                val cb = CheckBox(this@MainActivity).apply {
                    text = app.label
                    isChecked = startSel.contains(app.pkg)
                    isEnabled = rgMode.checkedRadioButtonId != rbAll.id
                }
                checks[app.pkg] = cb
                listBox.addView(cb)
            }
            if (apps.isEmpty()) listBox.addView(TextView(this@MainActivity).apply { text = getString(R.string.no_apps_found) })
            appsLoaded = true
            dialog.getButton(androidx.appcompat.app.AlertDialog.BUTTON_POSITIVE).isEnabled = true
        }
        dialog.setOnDismissListener { enumeration.cancel() }
    }

    private data class AppEntry(val pkg: String, val label: String)

    /**
     * All apps that can use the network (hold the INTERNET permission) — the meaningful set
     * for split tunnelling, the same approach WireGuard uses. Excludes this app itself;
     * sorted by display label.
     *
     * Enumeration needs `QUERY_ALL_PACKAGES` (declared in the manifest) to see past the
     * Android 11+ (API 30) package-visibility filter. We list packages with a LIGHT
     * `getInstalledApplications(0)` and check INTERNET per-package via `checkPermission`,
     * rather than one heavy `getInstalledPackages(GET_PERMISSIONS)`: the latter packs every
     * app's full permission array into a single Binder reply, which on app-heavy devices
     * blows the ~1 MB transaction limit and comes back SILENTLY TRUNCATED — that dropped
     * apps like Firefox from the picker. INTERNET is an install-time (normal) permission, so
     * `checkPermission` == GRANTED exactly when the app declares it.
     */
    private fun loadSelectableApps(): List<AppEntry> {
        val pm = packageManager
        val apps = try {
            if (Build.VERSION.SDK_INT >= 33)
                pm.getInstalledApplications(PackageManager.ApplicationInfoFlags.of(0L))
            else
                @Suppress("DEPRECATION") pm.getInstalledApplications(0)
        } catch (_: Exception) { emptyList() }
        val out = ArrayList<AppEntry>()
        for (ai in apps) {
            val pkg = ai.packageName ?: continue
            if (pkg == packageName) continue
            if (!runCatching { pm.checkPermission(Manifest.permission.INTERNET, pkg) ==
                    PackageManager.PERMISSION_GRANTED }.getOrDefault(false)) continue
            val label = try { pm.getApplicationLabel(ai).toString() } catch (_: Exception) { pkg }
            out.add(AppEntry(pkg, label))
        }
        out.sortBy { it.label.lowercase() }
        return out
    }

    /** Duplicate a profile (inserted right after it, name + " (copy)"). */
    private fun duplicateProfile(i: Int) {
        val p = profiles.getOrNull(i) ?: return
        val name = getString(R.string.duplicate_suffix, p.name)
        try {
            val candidate = profiles.map { it.copy() }.toMutableList()
            candidate.add(i + 1, Profile(name, p.text))
            // Insertion before the active row must retain the same active profile.
            val candidateActive = if (activeIndex > i) activeIndex + 1 else activeIndex
            persistCandidate(candidate, candidateActive)
            profiles.clear(); profiles.addAll(candidate); activeIndex = candidateActive
        } catch (e: Exception) {
            Toast.makeText(this, e.message ?: "Profile cannot be duplicated", Toast.LENGTH_LONG).show()
            return
        }
        reach.clear()               // indices shifted → re-probe
        renderProfileList()
    }

    /** Reorder a profile up (-1) or down (+1); keeps the active selection on the same entry. */
    /**
     * Index to make active after appending a profile: the new one normally, but the
     * unchanged current one while a tunnel is up. Creating or importing a profile must not
     * become a back-door profile switch on a live connection.
     */
    private fun activeAfterAdd(candidateSize: Int): Int =
        if (isConnected || isConnecting || isDisconnecting || isTrustedPaused) activeIndex
        else candidateSize - 1

    private fun moveProfile(i: Int, delta: Int) {
        val j = i + delta
        if (j < 0 || j >= profiles.size) return
        val candidate = profiles.map { it.copy() }.toMutableList()
        val moved = candidate.removeAt(i)
        candidate.add(j, moved)
        val candidateActive = when (activeIndex) { i -> j; j -> i; else -> activeIndex }
        try { persistCandidate(candidate, candidateActive) }
        catch (e: Exception) {
            Toast.makeText(this, e.message ?: "Could not save profiles", Toast.LENGTH_LONG).show()
            return
        }
        profiles.clear(); profiles.addAll(candidate); activeIndex = candidateActive
        reach.clear()               // indices shifted → re-probe
        renderProfileList()
    }

    /** Share a profile as a compact qeli:// link + QR (copy to clipboard, or the Android
     *  share sheet). The link imports on every qeli client and the server's /api/share. */
    private fun shareProfile(i: Int) {
        val p = profiles.getOrNull(i) ?: return
        val link = try {
            VpnConfig.parse(p.text).toQeliUri(p.name)
        } catch (e: Exception) {
            Toast.makeText(this, getString(R.string.cant_share, e.message ?: ""), Toast.LENGTH_LONG).show(); return
        }
        val dens = resources.displayMetrics.density
        fun dp(v: Int) = (v * dens).toInt()
        val qr = try {
            com.journeyapps.barcodescanner.BarcodeEncoder()
                .encodeBitmap(link, com.google.zxing.BarcodeFormat.QR_CODE, dp(240), dp(240))
        } catch (_: Exception) { null }
        val box = android.widget.LinearLayout(this).apply {
            orientation = android.widget.LinearLayout.VERTICAL
            setPadding(0, dp(16), 0, 0)
            if (qr != null) addView(android.widget.ImageView(context).apply {
                setImageBitmap(qr)
                layoutParams = android.widget.LinearLayout.LayoutParams(dp(240), dp(240))
                    .apply { gravity = android.view.Gravity.CENTER_HORIZONTAL }
            })
            addView(android.widget.TextView(context).apply {
                text = link; setTextIsSelectable(true); textSize = 12f
                setPadding(dp(16), dp(12), dp(16), 0)
            })
        }
        MaterialAlertDialogBuilder(this)
            .setTitle(getString(R.string.share_title, p.name))
            .setView(android.widget.ScrollView(this).apply { addView(box) })
            .setNeutralButton(R.string.copy) { _, _ ->
                (getSystemService(CLIPBOARD_SERVICE) as android.content.ClipboardManager)
                    .setPrimaryClip(android.content.ClipData.newPlainText("qeli", link))
                Toast.makeText(this, getString(R.string.link_copied), Toast.LENGTH_SHORT).show()
            }
            .setPositiveButton(R.string.share) { _, _ ->
                val send = android.content.Intent(android.content.Intent.ACTION_SEND).apply {
                    type = "text/plain"; putExtra(android.content.Intent.EXTRA_TEXT, link)
                }
                startActivity(android.content.Intent.createChooser(send, getString(R.string.share_chooser)))
            }
            .setNegativeButton(R.string.cancel, null)
            .show()
    }

    private fun deleteProfile(i: Int) {
        val p = profiles.getOrNull(i) ?: return
        val openedAtRevision = profileRevision
        MaterialAlertDialogBuilder(this)
            .setTitle(R.string.delete_profile).setMessage(getString(R.string.delete_profile_confirm, p.name))
            .setNegativeButton(R.string.cancel, null)
            .setPositiveButton(R.string.delete_profile) { _, _ ->
                if (profileRevision != openedAtRevision) {
                    Toast.makeText(this, R.string.profile_changed_during_edit, Toast.LENGTH_LONG).show()
                    return@setPositiveButton
                }
                val currentIndex = profiles.indexOfFirst { it === p }
                if (currentIndex < 0) return@setPositiveButton
                val candidate = profiles.map { it.copy() }.toMutableList()
                candidate.removeAt(currentIndex)
                if (candidate.isEmpty()) {
                    candidate.add(Profile(getString(R.string.default_profile_name), TEMPLATE))
                }
                // Removing an earlier row must retain the same active profile.
                val candidateActive = (activeIndex - if (currentIndex < activeIndex) 1 else 0)
                    .coerceIn(0, candidate.size - 1)
                try { persistCandidate(candidate, candidateActive) }
                catch (e: Exception) {
                    Toast.makeText(this, e.message ?: "Could not save profiles", Toast.LENGTH_LONG).show()
                    return@setPositiveButton
                }
                profiles.clear(); profiles.addAll(candidate); activeIndex = candidateActive
                reach.clear()
                renderProfileList(); renderActiveProfile()
            }.show()
    }

    // ── reachability (TCP connect) ───────────────────────────────────────--

    private fun configureAutoProbeTimer(runImmediately: Boolean) {
        autoProbeJob?.cancel()
        autoProbeJob = null
        cancelAutomaticProbeJobs()
        val prefs = getSharedPreferences(PREFS_STATE, Context.MODE_PRIVATE)
        if (!prefs.getBoolean(PREF_AUTO_PROBE, ProfileAutoProbePolicy.DEFAULT_ENABLED)) return

        autoProbeJob = lifecycleScope.launch {
            if (runImmediately) pingAll(manual = false)
            while (isActive) {
                val interval = ProfileAutoProbePolicy.clampIntervalSeconds(
                    prefs.getInt(
                        PREF_PROBE_INTERVAL_SECS,
                        ProfileAutoProbePolicy.DEFAULT_INTERVAL_SECS,
                    ),
                )
                delay(interval * 1_000L)
                pingAll(manual = false)
            }
        }
    }

    private fun cancelAutomaticProbeJobs() {
        val jobs = synchronized(automaticProbeJobs) {
            automaticProbeJobs.toList().also { automaticProbeJobs.clear() }
        }
        jobs.forEach(Job::cancel)
    }

    private fun launchReachabilityProbe(
        manual: Boolean,
        block: suspend kotlinx.coroutines.CoroutineScope.() -> Unit,
    ) {
        val job = lifecycleScope.launch(block = block)
        if (!manual) {
            automaticProbeJobs.add(job)
            job.invokeOnCompletion { automaticProbeJobs.remove(job) }
        }
    }

    private suspend fun <T> withReachabilityProbeSlot(block: suspend () -> T): T {
        reachabilityProbeSlots.acquire()
        return try { block() } finally { reachabilityProbeSlots.release() }
    }

    private fun pingActive(manual: Boolean = false) {
        if (isDisconnecting) return
        if (!manual) {
            val enabled = getSharedPreferences(PREFS_STATE, Context.MODE_PRIVATE)
                .getBoolean(PREF_AUTO_PROBE, ProfileAutoProbePolicy.DEFAULT_ENABLED)
            if (!enabled || isConnected || isConnecting || isTrustedPaused) return
        }
        val p = current() ?: return
        val idx = activeIndex
        val epoch = reachEpoch
        reach[idx] = -2L; renderActiveProfile()
        val cfg = try { VpnConfig.parse(p.text) } catch (_: Exception) { null }
        if (cfg == null) { reach[idx] = -1L; renderActiveProfile(); return }
        launchReachabilityProbe(manual) {
            // While connected, probe the in-tunnel gateway for a clean tunnel RTT
            // (probing the public IP loops back through the server and ~doubles it).
            val ms = if (isConnected && clientGateway.isNotEmpty()) {
                if (cfg.isUdp) udpPing(cfg, clientGateway)
                else tcpPing(clientGateway, cfg.port)
            } else {
                probe(p)
            }
            if (epoch == reachEpoch && !isDisconnecting
                && profiles.getOrNull(idx) === p) {
                reach[idx] = ms
                if (activeIndex == idx) renderActiveProfile()
            }
        }
    }

    private fun pingAll(manual: Boolean = false) {
        if (isDisconnecting) return
        val sweepPrefs = getSharedPreferences(PREFS_STATE, Context.MODE_PRIVATE)
        val sweepAt = System.currentTimeMillis()
        if (!manual) {
            if (!ProfileAutoProbePolicy.canStartSweep(
                    enabled = sweepPrefs.getBoolean(PREF_AUTO_PROBE, ProfileAutoProbePolicy.DEFAULT_ENABLED),
                    tunnelBusy = isConnected || isConnecting || isDisconnecting || isTrustedPaused,
                    nowMs = sweepAt,
                    lastSweepMs = lastAutoProbeAtMs,
                )) return
        }
        lastAutoProbeAtMs = sweepAt
        sweepPrefs.edit().putLong(PREF_LAST_AUTO_PROBE_MS, sweepAt).apply()
        val epoch = reachEpoch
        profiles.toList().forEachIndexed { i, p ->
            val ep = endpointOf(p)
            when {
                ep == null -> reach[i] = -1L
                // The profile we're connected through is known-reachable; probing it
                // (especially UDP) through the live full-tunnel is unreliable, so show
                // it green directly instead of risking a false red.
                isConnected && i == activeIndex -> reach[i] = 0L
                else -> {
                    reach[i] = -2L
                    launchReachabilityProbe(manual) {
                        val ms = withReachabilityProbeSlot { probe(p) }
                        if (epoch == reachEpoch && !isDisconnecting
                            && profiles.getOrNull(i) === p) {
                            reach[i] = ms
                            if (binding.viewProfiles.visibility == View.VISIBLE) renderProfileList()
                            if (activeIndex == i) renderActiveProfile()
                        }
                    }
                }
            }
        }
        renderProfileList()
    }

    private suspend fun tcpPing(host: String, port: Int): Long = withContext(Dispatchers.IO) {
        suspendCancellableCoroutine { continuation ->
            val socket = Socket()
            continuation.invokeOnCancellation { runCatching { socket.close() } }
            val result = try {
                val startedAt = System.currentTimeMillis()
                socket.connect(InetSocketAddress(host, port), 3000)
                System.currentTimeMillis() - startedAt
            } catch (_: Exception) {
                -1L
            } finally {
                runCatching { socket.close() }
            }
            if (continuation.isActive) continuation.resume(result)
        }
    }

    /** Protocol-aware reachability: TCP connect for TCP profiles, a real first-packet
     *  handshake probe for UDP (a TCP connect can't reach a UDP-only port). */
    private suspend fun probe(p: Profile): Long {
        val cfg = try { VpnConfig.parse(p.text) } catch (_: Exception) { return -1L }
        return if (cfg.isUdp) udpPing(cfg, cfg.serverAddress) else tcpPing(cfg.serverAddress, cfg.port)
    }

    /** Native UDP first-flight diagnostic. Rust uses the same hybrid PQ ClientHello,
     *  fragmentation, QUIC and obfs helpers as the live transport; Kotlin supplies only a
     *  credential-free profile and displays the measured time to any server reply. */
    private suspend fun udpPing(cfg: VpnConfig, host: String): Long = withContext(Dispatchers.IO) {
        suspendCancellableCoroutine { continuation ->
            val probeId = REACHABILITY_PROBE_IDS.updateAndGet { current ->
                if (current == Long.MAX_VALUE) 1L else current + 1L
            }
            continuation.invokeOnCancellation {
                TransportCore.cancelUdpReachability(probeId)
            }
            val result = runCatching {
                TransportCore.udpReachability(cfg.toTransportProbeIni(), host, probeId)
            }.getOrDefault(-1L)
            if (continuation.isActive) continuation.resume(result)
        }
    }

    // ── connect / disconnect ─────────────────────────────────────────────--

    // Toggle: disconnect if a tunnel is up OR a connect/reconnect attempt is running
    // (so the button can interrupt an endlessly-retrying connection); else connect.
    fun onConnectTap(v: View) {
        if (isDisconnecting) return
        if (isConnected || isConnecting || isTrustedPaused) disconnect() else connect()
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        maybeAutoConnect(intent)
        handleDeepLink(intent)
    }

    /** Handle a tapped `qeli://` deep link (from a messenger/browser): confirm, then import. */
    private fun handleDeepLink(intent: Intent?) {
        val data = intent?.data ?: return
        if (!"qeli".equals(data.scheme, ignoreCase = true)) return
        val raw = data.toString()
        intent.data = null  // consume so a recreation (rotation/theme) doesn't re-import
        val label = qeliLabel(raw) ?: "profile"
        MaterialAlertDialogBuilder(this)
            .setTitle(R.string.import_profile_title)
            .setMessage(getString(R.string.import_profile_msg, label))
            .setNegativeButton(R.string.cancel, null)
            .setPositiveButton(R.string.import_config) { _, _ -> addProfileFromQeliUri(raw) }
            .show()
    }

    /** Honor a one-tap connect request from the Quick Settings tile. Consumes the extra so a
     *  later configuration change / recreation doesn't reconnect on its own. */
    private fun maybeAutoConnect(intent: Intent?) {
        if (intent?.getBooleanExtra(EXTRA_AUTO_CONNECT, false) != true) return
        intent.removeExtra(EXTRA_AUTO_CONNECT)
        if (!isConnected && !isConnecting && !isDisconnecting && !isTrustedPaused) connect()
    }

    private fun connect() = startConnectRequest(reconfigure = false)

    /** A settings edit may replace an active attempt, but never steal a permission callback. */
    private fun reconnectForSettings() = startConnectRequest(reconfigure = true)

    private fun startConnectRequest(reconfigure: Boolean) {
        if (isDisconnecting || connectRequest.hasOutstandingResult ||
            (!reconfigure && (isConnected || isConnecting || isTrustedPaused))) return
        val p = current() ?: return
        // Revalidate saved text through the strict shared parser at activation.
        val cfg = try { VpnConfig.parse(p.text) } catch (e: Exception) {
            Toast.makeText(this, getString(R.string.profile_config_invalid, e.message ?: ""), Toast.LENGTH_LONG).show(); return
        }
        if (cfg.serverAddress.isBlank() || cfg.serverAddress == "SERVER_IP_OR_HOST") {
            Toast.makeText(this, getString(R.string.set_real_server), Toast.LENGTH_LONG).show()
            binding.tabs.getTabAt(1)?.select(); showEditor(activeIndex); return
        }
        if (!connectRequest.begin(cfg, reconfigure)) return
        appendLog("Connecting \"${p.name}\"")
        setConnectingState()
        if (Build.VERSION.SDK_INT >= 33 &&
            ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
            connectRequest.awaitPermission(VpnConnectRequest.Permission.NOTIFICATION)
            try { notificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS) }
            catch (e: Exception) {
                connectRequest.launchFailed(VpnConnectRequest.Permission.NOTIFICATION)
                appendLog("Permission request error: ${e.message}"); setDisconnectedState()
            }
            return
        }
        proceedWithVpnPermission()
    }

    private fun proceedWithVpnPermission() {
        if (!connectRequest.isActive) return
        try {
            val vpnIntent = VpnService.prepare(this)
            if (vpnIntent != null) {
                connectRequest.awaitPermission(VpnConnectRequest.Permission.VPN)
                vpnPrepareLauncher.launch(vpnIntent)
            } else startVpnService()
        } catch (e: Exception) {
            connectRequest.launchFailed(VpnConnectRequest.Permission.VPN)
            appendLog("Error: ${e.message}"); setDisconnectedState()
        }
    }

    private fun startVpnService() {
        val reconfigure = connectRequest.reconfigure
        val cfg = connectRequest.takeConfiguration() ?: return
        try {
            val intent = Intent(this, VpnServiceImpl::class.java).apply {
                action = if (reconfigure) VpnServiceImpl.ACTION_RECONFIGURE else VpnServiceImpl.ACTION_CONNECT
                putExtra(VpnServiceImpl.EXTRA_CONFIG, cfg)
            }
            startForegroundService(intent)
        } catch (e: Exception) {
            appendLog("Service error: ${e.message}"); setDisconnectedState()
        }
    }

    private fun disconnect() {
        connectRequest.cancel()
        appendLog("Disconnecting…")
        setDisconnectingState()
        try {
            // startService (not stopService) so the service processes ACTION_DISCONNECT,
            // sets userRequestedDisconnect and tears the tunnel down cleanly.
            startService(Intent(this, VpnServiceImpl::class.java).apply { action = VpnServiceImpl.ACTION_DISCONNECT })
        } catch (e: Exception) {
            appendLog("Disconnect error: ${e.message}")
            setErrorState(e.message)
        }
    }

    private fun requestBatteryOptimizationExclusion() {
        val pm = getSystemService(POWER_SERVICE) as PowerManager
        if (!pm.isIgnoringBatteryOptimizations(packageName)) {
            try { startActivity(Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS).apply { data = Uri.parse("package:$packageName") }) }
            catch (e: Exception) { Log.w("VpnMain", "battery opt: ${e.message}") }
        }
    }

    // ── UI state ──────────────────────────────────────────────────────────--

    private fun setConnectingState() {
        updateJob?.cancel(); updateJob = null
        isConnected = false; isConnecting = true; isDisconnecting = false; isTrustedPaused = false
        binding.btnPing.isEnabled = true
        binding.btnCheckAll.isEnabled = true
        binding.statusIndicator.backgroundTintList = csl(R.color.status_connecting)
        binding.tvStatus.text = getString(R.string.connecting)
        binding.tvRingHint.text = getString(R.string.tap_to_cancel)
        binding.tvIp.visibility = View.GONE
        binding.tvConnectionStep.visibility = View.VISIBLE; binding.tvConnectionStep.text = getString(R.string.status_starting)
        binding.tvSpeed.visibility = View.GONE
        binding.statsCard.visibility = View.GONE
        startRingSpin()
    }

    private fun setDisconnectingState() {
        updateJob?.cancel(); updateJob = null
        if (!isDisconnecting) reachEpoch++
        isConnected = false; isConnecting = false; isDisconnecting = true; isTrustedPaused = false
        clientIp = ""
        clientGateway = ""
        binding.btnPing.isEnabled = false
        binding.btnCheckAll.isEnabled = false
        binding.statusIndicator.backgroundTintList = csl(R.color.status_connecting)
        binding.tvStatus.text = getString(R.string.disconnecting)
        binding.tvRingHint.text = getString(R.string.disconnecting)
        binding.tvIp.visibility = View.GONE
        binding.tvConnectionStep.visibility = View.VISIBLE
        binding.tvConnectionStep.text = getString(R.string.disconnecting)
        binding.tvSpeed.visibility = View.GONE
        binding.statsCard.visibility = View.GONE
        startRingSpin()
    }

    private fun setDisconnectedState() {
        updateJob?.cancel(); updateJob = null
        isConnected = false; isConnecting = false; isDisconnecting = false; isTrustedPaused = false
        clientIp = ""; clientGateway = ""
        binding.btnPing.isEnabled = true
        binding.btnCheckAll.isEnabled = true
        binding.statusIndicator.backgroundTintList = csl(R.color.status_disconnected)
        binding.tvStatus.text = getString(R.string.disconnected)
        binding.tvRingHint.text = getString(R.string.tap_to_connect)
        binding.tvIp.visibility = View.GONE
        binding.tvConnectionStep.visibility = View.GONE
        binding.tvSpeed.visibility = View.GONE
        binding.statsCard.visibility = View.GONE
        stopRingSpin()
    }

    private fun setConnectedState() {
        isConnected = true; isConnecting = false; isDisconnecting = false; isTrustedPaused = false
        binding.btnPing.isEnabled = true
        binding.btnCheckAll.isEnabled = true
        binding.statusIndicator.backgroundTintList = csl(R.color.status_connected)
        binding.tvStatus.text = getString(R.string.connected)
        binding.tvRingHint.text = getString(R.string.tap_to_disconnect)
        if (clientIp.isNotEmpty()) { binding.tvIp.text = getString(R.string.ip_label, clientIp); binding.tvIp.visibility = View.VISIBLE }
        binding.tvConnectionStep.text = getString(R.string.tunnel_active); binding.tvConnectionStep.visibility = View.VISIBLE
        binding.tvSpeed.text = "↓ 0 B/s   ↑ 0 B/s"; binding.tvSpeed.visibility = View.VISIBLE
        // Show + seed the stats card from the service (covers Activity recreation).
        binding.statsCard.visibility = View.VISIBLE
        updateStats(VpnServiceImpl.liveBytesUp, VpnServiceImpl.liveBytesDown)
        stopRingSpin()
        maybeCheckForUpdates()
    }

    private fun setTrustedWaitingState() {
        updateJob?.cancel(); updateJob = null
        isConnected = false; isConnecting = false; isDisconnecting = false; isTrustedPaused = true
        clientIp = ""
        binding.btnPing.isEnabled = true
        binding.btnCheckAll.isEnabled = true
        binding.statusIndicator.backgroundTintList = csl(R.color.status_connecting)
        binding.tvStatus.text = getString(R.string.trusted_wifi_waiting)
        binding.tvRingHint.text = getString(R.string.tap_to_cancel_resume)
        binding.tvIp.visibility = View.GONE
        binding.tvConnectionStep.visibility = View.VISIBLE
        binding.tvConnectionStep.text = getString(
            R.string.trusted_wifi_waiting_detail,
            VpnServiceImpl.liveTrustedSsid.ifBlank { getString(R.string.trusted_wifi_unknown) },
        )
        binding.tvSpeed.visibility = View.GONE
        binding.statsCard.visibility = View.GONE
        stopRingSpin()
    }

    private fun setErrorState(error: String?) {
        updateJob?.cancel(); updateJob = null
        isConnected = false; isConnecting = false; isDisconnecting = false; isTrustedPaused = false
        clientIp = ""; clientGateway = ""
        binding.btnPing.isEnabled = true
        binding.btnCheckAll.isEnabled = true
        binding.statusIndicator.backgroundTintList = csl(R.color.status_error)
        binding.tvStatus.text = getString(R.string.error)
        binding.tvRingHint.text = getString(R.string.tap_to_retry)
        binding.tvIp.visibility = View.GONE
        binding.tvConnectionStep.text = error ?: getString(R.string.unknown_error); binding.tvConnectionStep.visibility = View.VISIBLE
        binding.tvSpeed.visibility = View.GONE
        binding.statsCard.visibility = View.GONE
        stopRingSpin()
    }

    private fun updateUi(status: String?, error: String?) {
        val wasLocked = isConnected || isConnecting || isDisconnecting || isTrustedPaused
        when (status) {
            VpnServiceImpl.STATUS_CONNECTING -> setConnectingState()
            VpnServiceImpl.STATUS_CONNECTED -> setConnectedState()
            VpnServiceImpl.STATUS_DISCONNECTING -> setDisconnectingState()
            VpnServiceImpl.STATUS_WAITING_TRUSTED -> setTrustedWaitingState()
            VpnServiceImpl.STATUS_DISCONNECTED -> setDisconnectedState()
            VpnServiceImpl.STATUS_ERROR -> setErrorState(error)
        }
        // Profile switching is locked while the tunnel is up, and the rows render that as
        // dimming — so the list has to be redrawn whenever we cross that boundary, or the
        // lock stays visible after a disconnect (and invisible after a connect).
        if (wasLocked != (isConnected || isConnecting || isDisconnecting || isTrustedPaused)) renderProfileList()
        if (wasLocked && !isConnected && !isConnecting && !isDisconnecting && !isTrustedPaused) {
            pingAll(manual = false)
        }
        // The protection card is worded in the present tense only while connected.
        renderConnectionInfo()
    }

    /** Live speed readout from the service's per-second stats broadcast. */
    private fun updateSpeed(upRate: Long, downRate: Long) {
        if (!isConnected) return
        binding.tvSpeed.visibility = View.VISIBLE
        binding.tvSpeed.text = "↓ ${fmtRate(downRate)}   ↑ ${fmtRate(upRate)}"
    }

    private fun fmtRate(bps: Long): String = when {
        bps >= 1024 * 1024 -> String.format(java.util.Locale.US, "%.1f MB/s", bps / (1024.0 * 1024.0))
        bps >= 1024 -> String.format(java.util.Locale.US, "%.1f KB/s", bps / 1024.0)
        else -> "$bps B/s"
    }

    /** Cumulative traffic totals + session uptime (from the per-second stats
     *  broadcast). Uptime is derived from the service's connect timestamp so it
     *  stays correct across Activity recreation. */
    private fun updateStats(upTotal: Long, downTotal: Long) {
        if (!isConnected) return
        binding.tvUp.text = fmtBytes(upTotal)
        binding.tvDown.text = fmtBytes(downTotal)
        val started = VpnServiceImpl.liveConnectedAt
        binding.tvUptime.text =
            if (started > 0) fmtUptime(System.currentTimeMillis() - started) else "00:00:00"
    }

    private fun fmtBytes(b: Long): String = when {
        b >= 1024L * 1024 * 1024 -> String.format(java.util.Locale.US, "%.2f GB", b / (1024.0 * 1024.0 * 1024.0))
        b >= 1024 * 1024 -> String.format(java.util.Locale.US, "%.1f MB", b / (1024.0 * 1024.0))
        b >= 1024 -> String.format(java.util.Locale.US, "%.1f KB", b / 1024.0)
        else -> "$b B"
    }

    private fun fmtUptime(ms: Long): String {
        val s = (ms / 1000).coerceAtLeast(0)
        return String.format(java.util.Locale.US, "%02d:%02d:%02d", s / 3600, (s % 3600) / 60, s % 60)
    }

    // ── connect-ring spin animation ──────────────────────────────────────--

    /** Continuously spin the gradient ring (used while connecting). The power
     *  glyph is a sibling view, so only the gradient rotates. */
    private fun startRingSpin() {
        if (ringSpin?.isRunning == true) return
        ringSpin = android.animation.ObjectAnimator.ofFloat(binding.ringGradient, View.ROTATION, 0f, 360f).apply {
            duration = 1100
            repeatCount = android.animation.ValueAnimator.INFINITE
            interpolator = android.view.animation.LinearInterpolator()
            start()
        }
    }

    private fun stopRingSpin() {
        ringSpin?.cancel(); ringSpin = null
        // ease back to the resting angle
        binding.ringGradient.animate().rotation(0f).setDuration(220).start()
    }

    private fun csl(colorRes: Int) = android.content.res.ColorStateList.valueOf(getColor(colorRes))

    /// Renders the log timestamp in the shape picked in Settings. Mirrors the Rust
    /// `util::log_timestamp` (and the server's `[logging] time_format`) value for
    /// value, so phone and server logs line up; an unknown value degrades to the
    /// default instead of throwing.
    private fun logStamp(timestampMs: Long = System.currentTimeMillis()): String {
        // Cached field, not a prefs read: appendLog runs per line and a reconnect
        // storm is exactly the path this screen was hardened against.
        val fmt = logTimeFormat
        if (fmt == "none" || fmt == "off") return ""
        val now = timestampMs
        if (fmt == "epoch" || fmt == "unix") {
            return "${now / 1000}.${(now % 1000).toString().padStart(3, '0')}"
        }
        val pattern = when (fmt) {
            "rfc3339", "iso8601" -> "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'"
            "datetime" -> "yyyy-MM-dd HH:mm:ss.SSS"
            else -> "HH:mm:ss.SSS"
        }
        val sdf = java.text.SimpleDateFormat(pattern, java.util.Locale.US)
        // rfc3339 is UTC by contract — that is the point of choosing it.
        if (fmt == "rfc3339" || fmt == "iso8601") {
            sdf.timeZone = java.util.TimeZone.getTimeZone("UTC")
        }
        return sdf.format(java.util.Date(now))
    }

    private fun currentDiagnosticSessionId(): String =
        getSharedPreferences(PREFS_STATE, Context.MODE_PRIVATE)
            .getString(PREF_DIAGNOSTIC_SESSION_ID, "")
            .orEmpty()

    private fun clearDisplayedLog() {
        binding.tvLog.text = ""
        logLineCount = 0
    }

    private fun restoreDiagnosticLog() {
        clearDisplayedLog()
        displayedLogEpoch = diagnosticJournal.epoch
        restoringLog = true
        val completion = diagnosticJournal.read()
        logRestoreJob = lifecycleScope.launch {
            try {
                val snapshot = completion.await()
                if (snapshot.epoch == diagnosticJournal.epoch) {
                    clearDisplayedLog()
                    snapshot.entries.forEach { renderLog(it, updateConnectionStep = false) }
                    restoredThroughSequence = snapshot.throughSequence
                    restoreLiveRecords.filter { it.epoch == snapshot.epoch && it.sequence > snapshot.throughSequence }
                        .sortedBy { it.sequence }.forEach { renderLog(it.entry, updateConnectionStep = false) }
                }
            } catch (_: Exception) {
                // Live broadcasts have already been displayed; a cancelled/failed restore must
                // not replace them with an empty snapshot.
            } finally {
                restoringLog = false
                restoreLiveRecords.clear()
            }
        }
    }

    private fun resetLogEpoch(epoch: Long) {
        logRestoreJob?.cancel()
        restoringLog = false
        restoreLiveRecords.clear()
        restoredThroughSequence = 0
        displayedLogEpoch = epoch
        clearDisplayedLog()
    }

    private fun acceptLog(record: JournalRecord, updateConnectionStep: Boolean = true) {
        if (record.epoch != diagnosticJournal.epoch) return
        if (displayedLogEpoch != record.epoch) resetLogEpoch(record.epoch)
        if (record.sequence <= restoredThroughSequence) return
        if (restoringLog) {
            if (restoreLiveRecords.size >= MAX_LOG_LINES) restoreLiveRecords.removeFirst()
            restoreLiveRecords.addLast(record)
        }
        renderLog(record.entry, updateConnectionStep)
    }

    private fun invalidatePendingReport() {
        reportJob?.cancel()
        reportExpiryJob?.cancel()
        pendingReport?.fill(0)
        pendingReport = null
        pendingReportEpoch = -1
        pendingReportPrivacyRevision = -1
    }

    private fun showDiagnosticExport() {
        if (reportJob?.isActive == true || pendingReport != null) return
        MaterialAlertDialogBuilder(this)
            .setTitle(R.string.diagnostic_report)
            .setMessage(R.string.diagnostic_report_desc)
            .setPositiveButton(R.string.report_current) { _, _ -> prepareDiagnosticExport(lastError = false) }
            .setNeutralButton(R.string.report_last_error) { _, _ -> prepareDiagnosticExport(lastError = true) }
            .setNegativeButton(R.string.cancel, null)
            .show()
    }

    private fun prepareDiagnosticExport(lastError: Boolean) {
        if (reportJob?.isActive == true || pendingReport != null) return
        val exportEpoch = diagnosticJournal.epoch
        val privacyRevision = diagnosticJournal.privacyRevision
        reportJob = lifecycleScope.launch {
            try {
                val report = if (lastError) diagnosticJournal.exportLastError().await()
                    else diagnosticJournal.exportCurrent().await()
                if (report == null) {
                    Toast.makeText(this@MainActivity, R.string.report_not_available, Toast.LENGTH_LONG).show()
                    return@launch
                }
                if (exportEpoch != diagnosticJournal.epoch || privacyRevision != diagnosticJournal.privacyRevision) return@launch
                val version = appVersion()
                val bytes = withContext(Dispatchers.IO) {
                    JSONObject(report).put("exporter_app_version", version).toString(2).toByteArray(Charsets.UTF_8)
                        .also { check(it.size <= AndroidDiagnosticJournal.REPORT_LIMIT) }
                }
                if (exportEpoch != diagnosticJournal.epoch || privacyRevision != diagnosticJournal.privacyRevision) {
                    bytes.fill(0)
                    return@launch
                }
                pendingReport = bytes
                pendingReportEpoch = exportEpoch
                pendingReportPrivacyRevision = privacyRevision
                // A document picker can remain open indefinitely. Retain at most one bounded
                // export for five minutes; never persist an unrequested intermediate file.
                reportExpiryJob = lifecycleScope.launch {
                    delay(5 * 60 * 1000L)
                    pendingReport?.fill(0)
                    pendingReport = null
                }
                diagnosticExportLauncher.launch(if (lastError) "qeli-last-error.json" else "qeli-diagnostics.json")
            } catch (_: Exception) {
                if (isActive) Toast.makeText(this@MainActivity, R.string.report_failed, Toast.LENGTH_LONG).show()
            }
        }
    }

    private fun appendLog(
        msg: String,
        timestampMs: Long = System.currentTimeMillis(),
        sessionId: String = currentDiagnosticSessionId(),
        level: String = "info",
        updateConnectionStep: Boolean = true,
    ) {
        acceptLog(diagnosticJournal.append(msg, sessionId, level, timestampMs), updateConnectionStep)
    }

    private fun renderLog(entry: DiagnosticLogEntry, updateConnectionStep: Boolean) {
        val ts = logStamp(entry.timestampMs)
        val tv = binding.tvLog
        // append() upgrades the buffer to EDITABLE, so we can trim the oldest lines
        // IN PLACE below. The old split/join of the whole buffer ran on every line
        // (O(n) allocations); during a reconnect log storm that saturated the main
        // thread into an ANR. editableText.delete is O(chars removed) ≈ one line.
        tv.append(if (ts.isEmpty()) "${entry.message}\n" else "[$ts] ${entry.message}\n")
        logLineCount++
        if (logLineCount > MAX_LOG_LINES) {
            (tv.text as? android.text.Editable)?.let { ed ->
                var toDrop = logLineCount - MAX_LOG_LINES
                var cut = 0
                while (toDrop > 0) {
                    val nl = android.text.TextUtils.indexOf(ed, '\n', cut)
                    if (nl < 0) break
                    cut = nl + 1; toDrop--
                }
                if (cut > 0) { ed.delete(0, cut); logLineCount = MAX_LOG_LINES }
            }
        }
        if (updateConnectionStep) {
            binding.tvConnectionStep.text = entry.message
            binding.tvConnectionStep.visibility = View.VISIBLE
        }
        // Coalesce autoscroll: queue at most one fullScroll per frame. Posting one per
        // log line queued a full layout pass per line and amplified the storm.
        if (logAutoScroll && !pendingLogScroll) {
            pendingLogScroll = true
            binding.scrollLog.post {
                pendingLogScroll = false
                binding.scrollLog.fullScroll(View.FOCUS_DOWN)
            }
        }
    }
}
