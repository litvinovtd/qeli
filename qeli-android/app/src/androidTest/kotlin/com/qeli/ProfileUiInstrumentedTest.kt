package com.qeli

import android.content.Context
import android.net.Uri
import android.view.View
import android.view.ViewGroup
import android.widget.CheckBox
import android.widget.EditText
import android.widget.RadioGroup
import androidx.test.core.app.ActivityScenario
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.qeli.crypto.BackupCrypto
import com.qeli.model.VpnConfig
import java.io.File
import java.util.concurrent.TimeUnit
import org.json.JSONArray
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/** Actual Activity/dialog/PackageManager/Keystore/files; dialog roots use test-only reflection. */
@RunWith(AndroidJUnit4::class)
class ProfileUiInstrumentedTest {
    private val context: Context = ApplicationProvider.getApplicationContext()
    private var scenario: ActivityScenario<MainActivity>? = null
    private val missingPackage = "com.qeli.audit.notinstalled"
    private val current get() = context.getSharedPreferences("vpn_secure_v2", Context.MODE_PRIVATE)
    private fun call(owner: MainActivity, name: String, type: Class<*>, arg: Any) =
        MainActivity::class.java.getDeclaredMethod(name, type).apply { isAccessible = true }.invoke(owner, arg)
    private fun root(): View {
        val type = Class.forName("android.view.WindowManagerGlobal")
        val manager = type.getDeclaredMethod("getInstance").invoke(null)
        @Suppress("UNCHECKED_CAST")
        val views = type.getDeclaredField("mViews").apply { isAccessible = true }.get(manager) as List<View>
        return views.last { it.findViewById<View>(android.R.id.button1) != null }
    }
    private fun children(view: View): List<View> = listOf(view) + if (view is ViewGroup)
        (0 until view.childCount).flatMap { children(view.getChildAt(it)) } else emptyList()
    private fun await(message: String, predicate: () -> Boolean) {
        val until = System.nanoTime() + TimeUnit.SECONDS.toNanos(15)
        while (!predicate() && System.nanoTime() < until) Thread.sleep(25)
        assertTrue(message, predicate())
    }
    @Before fun prepare() {
        assumeTrue(InstrumentationRegistry.getArguments().getString("q29_private_fixture") == "1")
        context.getSharedPreferences(MainActivity.PREFS_STATE, Context.MODE_PRIVATE).edit()
            .putBoolean("battery_opt_requested", true).putBoolean(MainActivity.PREF_AUTO_CONNECT_LAUNCH, false)
            .putBoolean(MainActivity.PREF_AUTO_PROBE, false).putBoolean(MainActivity.PREF_TRUSTED_WIFI_ENABLED, false).commit()
        VpnServiceImpl.liveStatus = VpnServiceImpl.STATUS_DISCONNECTED
    }
    @After fun clean() { scenario?.close(); scenario = null }
    private fun launch(mode: String = "include") {
        val ini = VpnConfig(serverAddress = "127.0.0.1", port = 443, username = "ui-fixture",
            password = "fixture", killSwitch = false, appsMode = mode,
            apps = if (mode == "all") emptyList() else listOf(missingPackage)).toIni()
        val blob = JSONObject().put("active", 0).put("profiles", JSONArray().put(
            JSONObject().put("name", "UI fixture").put("cfg", ini))).toString()
        assertTrue(ProfileStore.open(context).edit().putString(ProfileStore.KEY_PROFILES, blob).commit())
        scenario = ActivityScenario.launch(MainActivity::class.java)
    }
    @Test fun cannotSaveAppSelectionBeforeEnumerationCompletes() {
        launch(); val before = ProfileStore.open(context).getString(ProfileStore.KEY_PROFILES, null)
        var enabledDuringLoad = false
        scenario!!.onActivity { owner ->
            call(owner, "showAppsDialog", Int::class.javaPrimitiveType!!, 0)
            val save = root().findViewById<View>(android.R.id.button1)
            assertTrue("fixture requires pending inventory", children(root()).any { it is android.widget.TextView &&
                it.text.toString() == context.getString(R.string.loading_apps) })
            enabledDuringLoad = save.isEnabled
            if (enabledDuringLoad) save.performClick()
        }
        // AlertDialog posts its listener; onActivity returning alone does not await persistence.
        InstrumentationRegistry.getInstrumentation().waitForIdleSync()
        assertEquals("early Save destroyed configured packages", before,
            ProfileStore.open(context).getString(ProfileStore.KEY_PROFILES, null))
        assertFalse("Save must wait for the inventory", enabledDuringLoad)
    }
    @Test fun appSelectionRetainsConfiguredPackageAbsentFromInventory() {
        launch()
        scenario!!.onActivity { call(it, "showAppsDialog", Int::class.javaPrimitiveType!!, 0) }
        await("app list did not load") {
            var ready = false
            scenario!!.onActivity { ready = children(root()).none { v ->
                v is android.widget.TextView && v.text.toString() == context.getString(R.string.loading_apps) } }
            ready
        }
        scenario!!.onActivity { root().findViewById<View>(android.R.id.button1).performClick() }
        InstrumentationRegistry.getInstrumentation().waitForIdleSync()
        val cfg = VpnConfig.parse(requireNotNull(ProfileStore.activeProfileConfigText(context)))
        assertEquals("include", cfg.appsMode)
        assertEquals("missing configured package was silently dropped", listOf(missingPackage), cfg.apps)
    }
    @Test fun modeChangedDuringEnumerationEnablesLoadedCheckboxes() {
        launch("all")
        scenario!!.onActivity { owner ->
            call(owner, "showAppsDialog", Int::class.javaPrimitiveType!!, 0)
            val group = children(root()).filterIsInstance<RadioGroup>().single()
            group.check(group.getChildAt(1).id) // Choose include before enumeration returns.
        }
        await("installed app inventory absent") {
            var ready = false
            scenario!!.onActivity { ready = children(root()).filterIsInstance<CheckBox>().isNotEmpty() };ready
        }
        scenario!!.onActivity {
            val checks = children(root()).filterIsInstance<CheckBox>()
            assertTrue("loaded checkboxes kept the old all-mode disabled state", checks.all { it.isEnabled })
        }
    }
    @Test fun unreadableStoreExportReportsFailureWithoutThrowingOrReplacingCiphertext() {
        launch("all")
        val original = current.getString(ProfileStore.KEY_PROFILES, null)
        try {
            assertTrue(current.edit().putString(ProfileStore.KEY_PROFILES, "corrupt-envelope").commit())
            scenario!!.onActivity { call(it, "writeBackup", Uri::class.java, Uri.fromFile(File(context.filesDir, "unused-export.json"))) }
            assertEquals("corrupt-envelope", current.getString(ProfileStore.KEY_PROFILES, null))
        } finally { current.edit().putString(ProfileStore.KEY_PROFILES, original).commit() }
    }
    @Test fun plaintextAndEncryptedExportsContainTheExactArchive() {
        launch("all")
        val expected = requireNotNull(ProfileStore.open(context).getString(ProfileStore.KEY_PROFILES, null))
        for (pass in listOf("", "fixture-export-passphrase")) {
            val file = File(context.filesDir, if (pass.isEmpty()) "plain-export.json" else "encrypted-export.qeli")
            if (file.exists()) assertTrue(file.delete())
            scenario!!.onActivity { owner ->
                call(owner, "writeBackup", Uri::class.java, Uri.fromFile(file))
                children(root()).filterIsInstance<EditText>().single().setText(pass)
                root().findViewById<View>(android.R.id.button1).performClick()
            }
            await("export did not produce the exact archive") { runCatching {
                val bytes = file.readBytes()
                (if (pass.isEmpty()) decodeUtf8Strict(bytes) else BackupCrypto.decrypt(bytes, pass)) == expected
            }.getOrDefault(false) }
            assertTrue(file.delete())
        }
    }
    private fun assertTrustedWaitingCleared(terminal: String) {
        launch("all")
        scenario!!.onActivity { owner ->
            val update = MainActivity::class.java.getDeclaredMethod("updateUi", String::class.java, String::class.java)
                .apply { isAccessible = true }
            update.invoke(owner, VpnServiceImpl.STATUS_WAITING_TRUSTED, null)
            val paused = MainActivity::class.java.getDeclaredField("isTrustedPaused").apply { isAccessible = true }
            assertTrue(paused.getBoolean(owner))
            update.invoke(owner, terminal, "fixture terminal state")
            assertFalse("terminal state retained trusted pause and locked connect/profile switching", paused.getBoolean(owner))
        }
    }
    @Test fun disconnectedAfterTrustedWaitingClearsPause() = assertTrustedWaitingCleared(VpnServiceImpl.STATUS_DISCONNECTED)
    @Test fun errorAfterTrustedWaitingClearsPause() = assertTrustedWaitingCleared(VpnServiceImpl.STATUS_ERROR)
}
