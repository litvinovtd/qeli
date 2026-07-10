package com.qeli

import android.Manifest
import android.content.BroadcastReceiver
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.SharedPreferences
import android.content.pm.PackageManager
import android.net.Uri
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.PowerManager
import android.provider.Settings
import android.util.Log
import android.view.LayoutInflater
import android.view.View
import android.widget.CheckBox
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.lifecycle.lifecycleScope
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.google.android.material.tabs.TabLayout
import com.qeli.databinding.ActivityMainBinding
import com.qeli.databinding.ItemProfileBinding
import com.qeli.databinding.DialogConfigEditorBinding
import com.qeli.model.VpnConfig
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import com.qeli.protocol.ObfsStream
import com.qeli.protocol.Quic
import com.qeli.protocol.TlsHandshake
import org.json.JSONArray
import org.json.JSONObject
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetSocketAddress
import java.net.Socket
import java.security.SecureRandom

class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding
    private var isConnected = false
    // True while a connect/reconnect attempt is in flight (STATUS_CONNECTING) but not
    // yet established. The connect ring is a toggle: tapping it during this phase must
    // CANCEL the attempt, otherwise a server that keeps closing the connection leaves
    // the client retrying forever with no way to stop it from the UI.
    private var isConnecting = false
    private var clientIp = ""
    private var logLineCount = 0
    private var pendingConnect = false
    private var logAutoScroll = true
    // True while a fullScroll is already queued on scrollLog, so a burst of log lines
    // coalesces into a single scroll per frame instead of one layout pass per line.
    private var pendingLogScroll = false
    private var ringSpin: android.animation.ObjectAnimator? = null

    private val profiles = mutableListOf<Profile>()
    private var activeIndex = 0
    private val reach = HashMap<Int, Long>()   // profile index -> ping ms (-1 = down, -2 = checking)

    /** Encrypted-at-rest profile store: profiles carry the server password and
     *  obfs_key, so they must not sit in plaintext SharedPreferences. The master
     *  key lives in the Android Keystore (TEE/StrongBox where available). On first
     *  use this migrates any legacy plaintext profiles, then wipes the legacy copy
     *  so secrets no longer linger unencrypted. (docs/RELEASE-FIXES.md E1) */
    private val secureStore: SharedPreferences by lazy {
        // Same store the Quick Settings tile reads — see ProfileStore for the shared params.
        val store = ProfileStore.open(this)
        val legacy = getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        if (!store.contains(KEY_PROFILES)) {
            legacy.getString(KEY_PROFILES, null)?.let { raw ->
                store.edit().putString(KEY_PROFILES, raw).apply()
            }
        }
        if (legacy.contains(KEY_PROFILES)) {
            legacy.edit().remove(KEY_PROFILES).apply() // wipe the old plaintext secrets
        }
        store
    }

    /** A saved profile. [text] is flat-INI (the `[qeli]` schema). */
    private data class Profile(var name: String, var text: String)

    companion object {
        private const val MAX_LOG_LINES = 500
        private const val PREFS_NAME = "vpn"
        private const val KEY_PROFILES = "profiles_json"
        /** Intent extra: the Quick Settings tile ([QeliTileService]) sets this to true to ask
         *  the Activity to connect the active profile (it owns the consent / permission flows). */
        const val EXTRA_AUTO_CONNECT = "auto_connect"
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
# route_local = false      ; route LAN/RFC1918 through the tunnel
# dns = 1.1.1.1, 8.8.8.8   ; resolvers reached via the tunnel
"""
    }

    private val vpnPrepareLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { r -> if (r.resultCode == RESULT_OK) startVpnService() else { appendLog("VPN permission denied"); setDisconnectedState() } }

    private val importConfigLauncher = registerForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri -> if (uri != null) importConfigFromUri(uri) }

    private val qrScanLauncher = registerForActivityResult(ScanContract()) { result ->
        result.contents?.let { addProfileFromQeliUri(it) }
    }

    private val notificationPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { granted ->
        if (granted) { if (pendingConnect) { pendingConnect = false; proceedWithVpnPermission() } }
        else { appendLog("Notification permission denied - required for VPN"); setDisconnectedState() }
    }

    private val statusReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            val status = intent.getStringExtra(VpnServiceImpl.EXTRA_STATUS)
            val error = intent.getStringExtra(VpnServiceImpl.EXTRA_ERROR)
            val log = intent.getStringExtra(VpnServiceImpl.EXTRA_LOG)
            runOnUiThread {
                log?.let { appendLog(it) }
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
                    if (status == VpnServiceImpl.STATUS_CONNECTED) clientIp = intent.getStringExtra(VpnServiceImpl.EXTRA_IP) ?: ""
                    updateUi(status, error)
                }
            }
        }
    }

    // Update check (opt-in; notification-only): checked once per app run, only while connected.
    private var updateChecked = false
    private var updateUrl: String? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)
        setDisconnectedState()
        // After a theme switch / rotation the Activity is recreated but the VPN
        // foreground service keeps running — restore the real tunnel state so the
        // UI doesn't falsely show "Disconnected".
        restoreServiceState()

        loadProfiles()
        renderActiveProfile()
        renderProfileList()

        binding.tabs.addOnTabSelectedListener(object : TabLayout.OnTabSelectedListener {
            override fun onTabSelected(tab: TabLayout.Tab) { showTab(tab.position) }
            override fun onTabUnselected(tab: TabLayout.Tab) {}
            override fun onTabReselected(tab: TabLayout.Tab) {}
        })

        val filter = IntentFilter(VpnServiceImpl.BROADCAST_STATUS)
        if (Build.VERSION.SDK_INT >= 33) registerReceiver(statusReceiver, filter, RECEIVER_NOT_EXPORTED)
        else @Suppress("UnspecifiedRegisterReceiverFlag") registerReceiver(statusReceiver, filter)

        binding.btnImport.setOnClickListener { showImportChooser() }
        binding.btnNewProfile.setOnClickListener { showEditor(-1) }
        binding.btnCheckAll.setOnClickListener { pingAll() }
        binding.btnPing.setOnClickListener { pingActive() }
        binding.ringConnect.setOnClickListener { onConnectTap(it) }

        // Log tab toolbar
        binding.btnLogClear.setOnClickListener { binding.tvLog.text = ""; logLineCount = 0 }
        binding.btnLogCopy.setOnClickListener {
            val cm = getSystemService(CLIPBOARD_SERVICE) as ClipboardManager
            cm.setPrimaryClip(ClipData.newPlainText("qeli log", binding.tvLog.text))
            Toast.makeText(this, "Log copied", Toast.LENGTH_SHORT).show()
        }
        binding.btnLogAutoscroll.setOnClickListener { setAutoScroll(!logAutoScroll) }
        setAutoScroll(true)

        // Theme toggle (light <-> dark), persisted; AppCompat recreates the activity.
        updateThemeIcon()
        binding.btnTheme.setOnClickListener { QeliApp.setDark(this, !QeliApp.isDark(this)) }

        binding.tvVersion.text = "qeli ${appVersion()}"
        binding.tvVersion.setOnClickListener { showUpdatesDialog() }

        val prefs = getSharedPreferences("app_state", Context.MODE_PRIVATE)
        if (!prefs.getBoolean("battery_opt_requested", false)) {
            requestBatteryOptimizationExclusion(); prefs.edit().putBoolean("battery_opt_requested", true).apply()
        }
        pingActive()

        // Launched by the Quick Settings tile? Connect the active profile now that the receiver
        // and UI are wired (so the connect flow's status/log updates land).
        maybeAutoConnect(intent)
    }

    override fun onDestroy() {
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
            1 -> { renderProfileList(); pingAll() }
            0 -> { renderActiveProfile(); pingActive() }
        }
    }

    /** App version string for the diagnostics footer, e.g. "v0.7.5 (build 705)". */
    private fun appVersion(): String = try {
        val pi = packageManager.getPackageInfo(packageName, 0)
        val code = if (Build.VERSION.SDK_INT >= 28) pi.longVersionCode else @Suppress("DEPRECATION") pi.versionCode.toLong()
        "v${pi.versionName} (build $code)"
    } catch (_: Exception) { "v?" }

    /** Just the numeric versionName (e.g. "0.7.5") for comparison — distinct from the
     *  footer's "v0.7.5 (build 705)". */
    private fun rawVersionName(): String = try {
        packageManager.getPackageInfo(packageName, 0).versionName ?: "0"
    } catch (_: Exception) { "0" }

    /** Opt-in auto update check: once per session, only while the tunnel is up (so the
     *  request travels inside the tunnel — hides the real IP + the "runs qeli" tell), fail-soft. */
    private fun maybeCheckForUpdates() {
        if (!QeliApp.isCheckUpdates(this) || updateChecked) return
        updateChecked = true
        if (!isConnected) return
        lifecycleScope.launch {
            val info = UpdateChecker.check(rawVersionName()) ?: return@launch
            if (info.isNewer) showUpdateAvailable(info)
        }
    }

    /** Reveal an available update in the footer + a toast; the footer opens the dialog. */
    private fun showUpdateAvailable(info: UpdateInfo) {
        updateUrl = info.url
        binding.tvVersion.text = "qeli ${appVersion()} — update available"
        Toast.makeText(this, "Update available: ${info.latest}", Toast.LENGTH_LONG).show()
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
            text = "Check for updates automatically"
            isChecked = QeliApp.isCheckUpdates(this@MainActivity)
            setOnCheckedChangeListener { _, on -> QeliApp.setCheckUpdates(this@MainActivity, on) }
        }
        val status = TextView(this).apply {
            setPadding(0, pad, 0, 0)
            updateUrl?.let { u -> text = "Update available — tap to open"; setOnClickListener { openUrl(u) } }
        }
        box.addView(toggle)
        box.addView(status)

        val dlg = MaterialAlertDialogBuilder(this)
            .setTitle("qeli ${appVersion()}")
            .setView(box)
            .setNeutralButton("Check now", null)   // overridden below so it doesn't auto-dismiss
            .setPositiveButton("Close", null)
            .create()
        dlg.show()
        dlg.getButton(android.app.AlertDialog.BUTTON_NEUTRAL).setOnClickListener {
            if (!isConnected) { status.text = "Connect first to check for updates privately"; return@setOnClickListener }
            status.text = "Checking…"
            lifecycleScope.launch {
                val info = UpdateChecker.check(rawVersionName())
                when {
                    info == null -> status.text = "Could not check for updates"
                    info.isNewer -> {
                        status.text = "Update available: ${info.latest} — tap to open"
                        status.setOnClickListener { openUrl(info.url) }
                        showUpdateAvailable(info)
                    }
                    else -> status.text = "You have the latest version"
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
            VpnServiceImpl.STATUS_CONNECTED -> { clientIp = VpnServiceImpl.liveIp; setConnectedState() }
            VpnServiceImpl.STATUS_CONNECTING -> setConnectingState()
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
        binding.btnLogAutoscroll.text = if (on) "Scroll ✓" else "Scroll"
        if (on) binding.scrollLog.post { binding.scrollLog.fullScroll(View.FOCUS_DOWN) }
    }

    // ── profiles ──────────────────────────────────────────────────────────--

    private fun current(): Profile? = profiles.getOrNull(activeIndex)

    private fun loadProfiles() {
        profiles.clear()
        val raw = secureStore.getString(KEY_PROFILES, null)
        if (raw != null) {
            try {
                val root = JSONObject(raw)
                activeIndex = root.optInt("active", 0)
                val arr = root.optJSONArray("profiles") ?: JSONArray()
                for (i in 0 until arr.length()) {
                    val p = arr.getJSONObject(i)
                    // New format stores `cfg` (INI). Legacy stored `json` (JSON) or
                    // an old multi-profile {address,port,...}. Normalize all to INI.
                    val stored = p.optString("cfg", "").ifBlank {
                        p.optString("json", "").ifBlank { synthesizeJson(p) }
                    }
                    val ini = toIniText(stored)
                    profiles.add(Profile(p.optString("name", "profile"), ini))
                }
            } catch (e: Exception) { Log.e("VpnMain", "profiles load: ${e.message}") }
        }
        if (profiles.isEmpty()) { profiles.add(Profile("My server", TEMPLATE)); persist() }
        if (activeIndex !in profiles.indices) activeIndex = 0
    }

    /** Normalize stored profile text to INI: convert legacy JSON, pass INI through. */
    private fun toIniText(stored: String): String = try {
        if (stored.trimStart().startsWith("{")) VpnConfig.fromJson(stored).toIni() else stored
    } catch (_: Exception) { stored }

    // legacy old-multi-profile entry -> a config json (then normalized to INI)
    private fun synthesizeJson(p: JSONObject): String = JSONObject().apply {
        put("name", p.optString("name", "profile"))
        put("server", JSONObject().put("address", p.optString("address", "")).put("port", p.optInt("port", 443)))
        put("auth", JSONObject().put("username", p.optString("username", "phone")))
        put("routing", JSONObject().put("mode", "full-tunnel").put("add_default_gateway", true))
    }.toString()

    private fun persist() {
        val arr = JSONArray()
        for (p in profiles) arr.put(JSONObject().put("name", p.name).put("cfg", p.text))
        secureStore.edit()
            .putString(KEY_PROFILES, JSONObject().put("active", activeIndex).put("profiles", arr).toString())
            .apply()
    }

    /** Parsed address/port for display + ping; null on parse failure. */
    private fun endpointOf(p: Profile): Pair<String, Int>? = try {
        val c = VpnConfig.parse(p.text); Pair(c.serverAddress, c.port)
    } catch (_: Exception) { null }

    // ── editor dialog (text config) ──────────────────────────────────────--

    /** index = -1 to create a new profile. */
    private fun showEditor(index: Int) {
        val dlgBinding = DialogConfigEditorBinding.inflate(LayoutInflater.from(this))
        val editing = profiles.getOrNull(index)
        dlgBinding.editName.setText(editing?.name ?: "New profile")
        dlgBinding.editJson.setText(editing?.text ?: TEMPLATE)

        val dialog = MaterialAlertDialogBuilder(this)
            .setTitle(if (index < 0) "New profile" else "Edit profile")
            .setView(dlgBinding.root)
            .setNegativeButton(R.string.cancel, null)
            .setPositiveButton(R.string.save, null)   // override below to validate
            .create()
        dialog.show()
        dialog.getButton(android.app.AlertDialog.BUTTON_POSITIVE).setOnClickListener {
            val cfgText = dlgBinding.editJson.text.toString().trim()
            val cfg = try { VpnConfig.parse(cfgText) } catch (e: Exception) {
                Toast.makeText(this, "Invalid config: ${e.message}", Toast.LENGTH_LONG).show(); return@setOnClickListener
            }
            // Re-emit as canonical INI so the stored text stays tidy/consistent.
            val iniText = if (cfgText.trimStart().startsWith("{")) cfg.toIni() else cfgText
            var name = dlgBinding.editName.text.toString().trim()
            if (name.isBlank()) name = cfg.serverAddress.ifBlank { "profile" }
            if (index < 0) { profiles.add(Profile(name, iniText)); activeIndex = profiles.size - 1 }
            else { profiles[index].name = name; profiles[index].text = iniText }
            persist(); renderProfileList(); renderActiveProfile(); pingActive()
            dialog.dismiss()
        }
    }

    /** Offer the three ways to add a profile: file, QR scan, or pasted link. */
    private fun showImportChooser() {
        val options = arrayOf("Scan QR code", "Paste qeli:// link", "Import config file")
        MaterialAlertDialogBuilder(this)
            .setTitle("Add profile")
            .setItems(options) { _, which ->
                when (which) {
                    0 -> startQrScan()
                    1 -> showPasteLinkDialog()
                    2 -> try { importConfigLauncher.launch(arrayOf("text/plain", "application/json", "*/*")) }
                         catch (e: Exception) { Toast.makeText(this, "Cannot open file picker: ${e.message}", Toast.LENGTH_LONG).show() }
                }
            }
            .show()
    }

    private fun startQrScan() {
        val opts = ScanOptions()
            .setDesiredBarcodeFormats(ScanOptions.QR_CODE)
            .setPrompt("Scan a qeli:// QR code")
            .setBeepEnabled(false)
            .setOrientationLocked(false)
        qrScanLauncher.launch(opts)
    }

    private fun showPasteLinkDialog() {
        val input = EditText(this).apply { hint = "qeli://…"; setSingleLine(false) }
        MaterialAlertDialogBuilder(this)
            .setTitle("Paste qeli:// link")
            .setView(input)
            .setNegativeButton(R.string.cancel, null)
            .setPositiveButton(R.string.save) { _, _ -> addProfileFromQeliUri(input.text.toString()) }
            .show()
    }

    /** Parse a scanned/pasted qeli:// link and add it as a profile (stored as INI). */
    private fun addProfileFromQeliUri(raw: String) {
        try {
            val cfg = VpnConfig.fromQeliUri(raw)
            val label = qeliLabel(raw) ?: cfg.serverAddress
            profiles.add(Profile(label, cfg.toIni(label))); activeIndex = profiles.size - 1
            persist(); renderProfileList(); renderActiveProfile(); pingActive()
            binding.tabs.getTabAt(0)?.select()
            appendLog("Imported \"$label\" from QR/link")
            Toast.makeText(this, "Imported \"$label\"", Toast.LENGTH_SHORT).show()
        } catch (e: Exception) {
            Toast.makeText(this, "Invalid qeli:// link: ${e.message}", Toast.LENGTH_LONG).show()
        }
    }

    /** Extract the human label from a qeli:// fragment (#label), if present. */
    private fun qeliLabel(uri: String): String? {
        val frag = uri.substringAfter('#', "").trim()
        if (frag.isEmpty()) return null
        return try { Uri.decode(frag) } catch (_: Exception) { frag }
    }

    private fun importConfigFromUri(uri: Uri) {
        try {
            val text = contentResolver.openInputStream(uri)?.use { it.readBytes().decodeToString() }
                ?.trim() ?: throw IllegalStateException("Empty file")
            // A file may hold a qeli:// link, a JSON config, or an INI config.
            if (text.startsWith("qeli://")) { addProfileFromQeliUri(text); return }
            val cfg = VpnConfig.parse(text)   // validate (auto-detect INI/JSON)
            val ini = if (text.trimStart().startsWith("{")) cfg.toIni() else text
            val label = (commentLabel(text) ?: jsonName(text)).ifBlank { cfg.serverAddress }
            profiles.add(Profile(label, ini)); activeIndex = profiles.size - 1
            persist(); renderProfileList(); renderActiveProfile(); pingActive()
            binding.tabs.getTabAt(0)?.select()
            appendLog("Imported \"$label\"")
            Toast.makeText(this, "Imported \"$label\"", Toast.LENGTH_SHORT).show()
        } catch (e: Exception) {
            Toast.makeText(this, "Invalid config: ${e.message}", Toast.LENGTH_LONG).show()
        }
    }

    /** Leading `# label` comment line of an INI config, if present. */
    private fun commentLabel(text: String): String? =
        text.lineSequence().firstOrNull()?.trim()?.takeIf { it.startsWith("#") }?.removePrefix("#")?.trim()?.ifBlank { null }

    private fun jsonName(text: String): String =
        try { if (text.trimStart().startsWith("{")) JSONObject(text).optString("name", "") else "" } catch (_: Exception) { "" }

    // ── rendering ────────────────────────────────────────────────────────--

    private fun renderActiveProfile() {
        val p = current()
        binding.tvActiveProfile.text = p?.name ?: "—"
        val ms = reach[activeIndex]
        applyReach(binding.activeReachDot, binding.tvActiveReach, p, ms)
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
            row.rowSub.text = if (ep != null) "${ep.first}:${ep.second}" else "⚠ invalid config"
            applyReach(row.rowReachDot, null, p, reach[i])
            row.root.setOnClickListener {
                activeIndex = i; persist(); renderProfileList(); renderActiveProfile()
                binding.tabs.getTabAt(0)?.select()
                Toast.makeText(this, "Active: ${p.name}", Toast.LENGTH_SHORT).show()
            }
            row.rowEdit.setOnClickListener { showEditor(i) }
            row.rowDelete.setOnClickListener { deleteProfile(i) }
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
            ms == null -> "tap Ping to check"
            ms == -2L -> "checking…"
            ms < 0 -> "unreachable"
            else -> "reachable · ${ms} ms"
        }
    }

    private fun deleteProfile(i: Int) {
        val p = profiles.getOrNull(i) ?: return
        MaterialAlertDialogBuilder(this)
            .setTitle("Delete profile").setMessage("Delete \"${p.name}\"?")
            .setNegativeButton(R.string.cancel, null)
            .setPositiveButton(R.string.delete_profile) { _, _ ->
                profiles.removeAt(i)
                reach.clear()
                if (profiles.isEmpty()) profiles.add(Profile("My server", TEMPLATE))
                if (activeIndex >= profiles.size) activeIndex = profiles.size - 1
                persist(); renderProfileList(); renderActiveProfile()
            }.show()
    }

    // ── reachability (TCP connect) ───────────────────────────────────────--

    private fun pingActive() {
        val p = current() ?: return
        val idx = activeIndex
        reach[idx] = -2L; renderActiveProfile()
        val cfg = try { VpnConfig.parse(p.text) } catch (_: Exception) { null }
        if (cfg == null) { reach[idx] = -1L; renderActiveProfile(); return }
        lifecycleScope.launch {
            // While connected, probe the in-tunnel gateway for a clean tunnel RTT
            // (probing the public IP loops back through the server and ~doubles it).
            val ms = if (isConnected && clientIp.isNotEmpty()) {
                val gw = gatewayOf(clientIp)
                if (cfg.isUdp) udpPing(cfg, gw) else tcpPing(gw, cfg.port)
            } else {
                probe(p)
            }
            reach[idx] = ms
            if (activeIndex == idx) renderActiveProfile()
        }
    }

    private fun pingAll() {
        profiles.forEachIndexed { i, p ->
            val ep = endpointOf(p)
            when {
                ep == null -> reach[i] = -1L
                // The profile we're connected through is known-reachable; probing it
                // (especially UDP) through the live full-tunnel is unreliable, so show
                // it green directly instead of risking a false red.
                isConnected && i == activeIndex -> reach[i] = 0L
                else -> {
                    reach[i] = -2L
                    lifecycleScope.launch {
                        val ms = probe(p); reach[i] = ms
                        if (binding.viewProfiles.visibility == View.VISIBLE) renderProfileList()
                    }
                }
            }
        }
        renderProfileList()
    }

    private suspend fun tcpPing(host: String, port: Int): Long = withContext(Dispatchers.IO) {
        try {
            val s = Socket(); val t0 = System.currentTimeMillis()
            s.connect(InetSocketAddress(host, port), 3000)
            val ms = System.currentTimeMillis() - t0; try { s.close() } catch (_: Exception) {}
            ms
        } catch (_: Exception) { -1L }
    }

    /** Protocol-aware reachability: TCP connect for TCP profiles, a real first-packet
     *  handshake probe for UDP (a TCP connect can't reach a UDP-only port). */
    private suspend fun probe(p: Profile): Long {
        val cfg = try { VpnConfig.parse(p.text) } catch (_: Exception) { return -1L }
        return if (cfg.isUdp) udpPing(cfg, cfg.serverAddress) else tcpPing(cfg.serverAddress, cfg.port)
    }

    /** The server's in-tunnel gateway (`x.y.z.1` of the assigned tunnel IP). The
     *  profile listens on 0.0.0.0:port, so it is reachable here through the tunnel
     *  — probing it gives a clean one-way tunnel RTT. */
    private fun gatewayOf(ip: String): String {
        val o = ip.split(".")
        return if (o.size == 4) "${o[0]}.${o[1]}.${o[2]}.1" else ip
    }

    /** UDP reachability: send the SAME hybrid X25519+ML-KEM ClientHello a real
     *  connection sends (mode-framed: raw fake-tls / QUIC-wrapped / obfs-sealed) and
     *  treat ANY reply datagram as "server reachable". The server requires the
     *  X25519MLKEM768 share for the PQ tunnel and silently drops a non-PQ hello, so the
     *  probe MUST carry a real ML-KEM key to get a ServerHello back (otherwise every UDP
     *  profile shows a false red even when reachable). We only need a reply — the derived
     *  keys are thrown away. Correctly stays red when UDP is truly blocked (no reply). */
    private suspend fun udpPing(cfg: VpnConfig, host: String): Long = withContext(Dispatchers.IO) {
        val sock = try { DatagramSocket() } catch (_: Exception) { return@withContext -1L }
        val mlkem = try { MlKem.generate() } catch (_: Exception) {
            try { sock.close() } catch (_: Exception) {}; return@withContext -1L
        }
        try {
            sock.soTimeout = 1500
            sock.connect(InetSocketAddress(host, cfg.port))
            val pub = ByteArray(32).also { SecureRandom().nextBytes(it) }
            val sni = cfg.sni?.takeIf { it.isNotBlank() } ?: "www.microsoft.com"
            val hello = TlsHandshake.buildClientHelloPq(pub, mlkem.encapsulationKey, sni, padToMin = 1200)
            val framed = when {
                cfg.quicEnabled -> Quic.wrapLong(hello, Quic.generateConnectionId(), 0, 0x02)
                cfg.wireMode.equals("obfs", ignoreCase = true) ->
                    ObfsStream.datagramSeal(ObfsStream.deriveKey(cfg.obfsKey), hello)
                else -> hello
            }
            val recv = DatagramPacket(ByteArray(4096), 4096)
            val t0 = System.currentTimeMillis()
            repeat(2) { // one retry — a single UDP probe can be lost
                sock.send(DatagramPacket(framed, framed.size))
                try {
                    sock.receive(recv)
                    if (recv.length > 0) return@withContext System.currentTimeMillis() - t0
                } catch (_: java.net.SocketTimeoutException) { /* retry */ }
            }
            -1L
        } catch (_: Exception) {
            -1L
        } finally {
            try { mlkem.close() } catch (_: Exception) {}
            try { sock.close() } catch (_: Exception) {}
        }
    }

    // ── connect / disconnect ─────────────────────────────────────────────--

    // Toggle: disconnect if a tunnel is up OR a connect/reconnect attempt is running
    // (so the button can interrupt an endlessly-retrying connection); else connect.
    fun onConnectTap(v: View) { if (isConnected || isConnecting) disconnect() else connect() }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        maybeAutoConnect(intent)
    }

    /** Honor a one-tap connect request from the Quick Settings tile. Consumes the extra so a
     *  later configuration change / recreation doesn't reconnect on its own. */
    private fun maybeAutoConnect(intent: Intent?) {
        if (intent?.getBooleanExtra(EXTRA_AUTO_CONNECT, false) != true) return
        intent.removeExtra(EXTRA_AUTO_CONNECT)
        if (!isConnected && !isConnecting) connect()
    }

    private fun connect() {
        val p = current() ?: return
        val cfg = try { VpnConfig.parse(p.text) } catch (e: Exception) {
            Toast.makeText(this, "Profile config invalid: ${e.message}", Toast.LENGTH_LONG).show(); return
        }
        if (cfg.serverAddress.isBlank() || cfg.serverAddress == "SERVER_IP_OR_HOST") {
            Toast.makeText(this, "Edit the profile and set a real server address", Toast.LENGTH_LONG).show()
            binding.tabs.getTabAt(1)?.select(); showEditor(activeIndex); return
        }
        appendLog("Connecting \"${p.name}\"")
        setConnectingState()
        if (Build.VERSION.SDK_INT >= 33 &&
            ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
            pendingConnect = true
            notificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS); return
        }
        proceedWithVpnPermission()
    }

    private fun proceedWithVpnPermission() {
        try {
            val vpnIntent = VpnService.prepare(this)
            if (vpnIntent != null) vpnPrepareLauncher.launch(vpnIntent) else startVpnService()
        } catch (e: Exception) { appendLog("Error: ${e.message}"); setDisconnectedState() }
    }

    private fun startVpnService() {
        try {
            val cfg = VpnConfig.parse(current()!!.text)
            val intent = Intent(this, VpnServiceImpl::class.java).apply {
                action = VpnServiceImpl.ACTION_CONNECT
                putExtra(VpnServiceImpl.EXTRA_CONFIG, cfg)
            }
            if (Build.VERSION.SDK_INT >= 26) startForegroundService(intent) else startService(intent)
        } catch (e: Exception) {
            appendLog("Service error: ${e.message}"); setDisconnectedState()
        }
    }

    private fun disconnect() {
        appendLog("Disconnecting…")
        setDisconnectedState()
        try {
            // startService (not stopService) so the service processes ACTION_DISCONNECT,
            // sets userRequestedDisconnect and tears the tunnel down cleanly.
            startService(Intent(this, VpnServiceImpl::class.java).apply { action = VpnServiceImpl.ACTION_DISCONNECT })
        } catch (_: Exception) {}
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
        isConnected = false; isConnecting = true
        binding.statusIndicator.backgroundTintList = csl(R.color.status_connecting)
        binding.tvStatus.text = "Connecting…"
        binding.tvRingHint.text = "TAP TO CANCEL"
        binding.tvIp.visibility = View.GONE
        binding.tvConnectionStep.visibility = View.VISIBLE; binding.tvConnectionStep.text = "Starting…"
        binding.tvSpeed.visibility = View.GONE
        binding.statsCard.visibility = View.GONE
        startRingSpin()
    }

    private fun setDisconnectedState() {
        isConnected = false; isConnecting = false; clientIp = ""
        binding.statusIndicator.backgroundTintList = csl(R.color.status_disconnected)
        binding.tvStatus.text = "Disconnected"
        binding.tvRingHint.text = "TAP TO CONNECT"
        binding.tvIp.visibility = View.GONE
        binding.tvConnectionStep.visibility = View.GONE
        binding.tvSpeed.visibility = View.GONE
        binding.statsCard.visibility = View.GONE
        stopRingSpin()
    }

    private fun setConnectedState() {
        isConnected = true; isConnecting = false
        binding.statusIndicator.backgroundTintList = csl(R.color.status_connected)
        binding.tvStatus.text = "Connected"
        binding.tvRingHint.text = "TAP TO DISCONNECT"
        if (clientIp.isNotEmpty()) { binding.tvIp.text = "IP $clientIp"; binding.tvIp.visibility = View.VISIBLE }
        binding.tvConnectionStep.text = "Tunnel active"; binding.tvConnectionStep.visibility = View.VISIBLE
        binding.tvSpeed.text = "↓ 0 B/s   ↑ 0 B/s"; binding.tvSpeed.visibility = View.VISIBLE
        // Show + seed the stats card from the service (covers Activity recreation).
        binding.statsCard.visibility = View.VISIBLE
        updateStats(VpnServiceImpl.liveBytesUp, VpnServiceImpl.liveBytesDown)
        stopRingSpin()
        maybeCheckForUpdates()
    }

    private fun setErrorState(error: String?) {
        isConnected = false; isConnecting = false; clientIp = ""
        binding.statusIndicator.backgroundTintList = csl(R.color.status_error)
        binding.tvStatus.text = "Error"
        binding.tvRingHint.text = "TAP TO RETRY"
        binding.tvIp.visibility = View.GONE
        binding.tvConnectionStep.text = error ?: "Unknown error"; binding.tvConnectionStep.visibility = View.VISIBLE
        binding.tvSpeed.visibility = View.GONE
        binding.statsCard.visibility = View.GONE
        stopRingSpin()
    }

    private fun updateUi(status: String?, error: String?) {
        when (status) {
            VpnServiceImpl.STATUS_CONNECTING -> setConnectingState()
            VpnServiceImpl.STATUS_CONNECTED -> setConnectedState()
            VpnServiceImpl.STATUS_DISCONNECTED -> setDisconnectedState()
            VpnServiceImpl.STATUS_ERROR -> setErrorState(error)
        }
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

    private fun appendLog(msg: String) {
        val ts = java.text.SimpleDateFormat("HH:mm:ss", java.util.Locale.US).format(java.util.Date())
        val tv = binding.tvLog
        // append() upgrades the buffer to EDITABLE, so we can trim the oldest lines
        // IN PLACE below. The old split/join of the whole buffer ran on every line
        // (O(n) allocations); during a reconnect log storm that saturated the main
        // thread into an ANR. editableText.delete is O(chars removed) ≈ one line.
        tv.append("[$ts] $msg\n")
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
        binding.tvConnectionStep.text = msg; binding.tvConnectionStep.visibility = View.VISIBLE
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
