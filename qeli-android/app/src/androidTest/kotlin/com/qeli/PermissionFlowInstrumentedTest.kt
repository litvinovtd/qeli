package com.qeli
import android.app.ActivityManager
import android.content.Context
import android.content.Intent
import androidx.test.core.app.ActivityScenario
import androidx.test.core.app.ApplicationProvider
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.ext.junit.runners.AndroidJUnit4
import java.io.Closeable
import java.io.FileInputStream
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import org.json.JSONArray
import org.json.JSONObject
import org.junit.After
import org.junit.Before
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

/** Real Activity, registry, service and JNI; pending permission phase and results are test injections. */
@RunWith(AndroidJUnit4::class)
class PermissionFlowInstrumentedTest {
 private val context: Context = ApplicationProvider.getApplicationContext()
 private val instrumentation = InstrumentationRegistry.getInstrumentation()
 private var scenario: ActivityScenario<MainActivity>? = null
 private fun shell(command: String) = instrumentation.uiAutomation.executeShellCommand(command).use {
  FileInputStream(it.fileDescriptor).use { input -> input.readBytes().toString(Charsets.UTF_8) }
 }
 @Suppress("DEPRECATION") private fun service() = context.getSystemService(ActivityManager::class.java).getRunningServices(100)
  .firstOrNull { it.service.className == VpnServiceImpl::class.java.name }
 private fun await(message: String, condition: () -> Boolean) {
  val until = System.nanoTime() + TimeUnit.SECONDS.toNanos(10)
  while (!condition() && System.nanoTime() < until) Thread.sleep(25)
  assertTrue(message, condition())
 }
 @Before fun prepare() {
  context.stopService(Intent(context, VpnServiceImpl::class.java));await("old service remained") { service() == null }
  assertTrue(context.getSharedPreferences(MainActivity.PREFS_STATE, Context.MODE_PRIVATE).edit()
   .putBoolean("battery_opt_requested", true).putBoolean(MainActivity.PREF_AUTO_CONNECT_LAUNCH, false)
   .putBoolean(MainActivity.PREF_TRUSTED_WIFI_ENABLED, false).putBoolean(MainActivity.PREF_CONNECTION_DESIRED, false).commit())
  VpnServiceImpl.liveStatus = VpnServiceImpl.STATUS_DISCONNECTED
  shell("appops set com.qeli ACTIVATE_VPN allow")
 }
 @After fun clean() {
  scenario?.close()
  context.startService(Intent(context, VpnServiceImpl::class.java).setAction(VpnServiceImpl.ACTION_DISCONNECT))
  await("service remained after test") { service() == null }
 }
 private class StallPeer : Closeable {
  private val listener = ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"));val port get() = listener.localPort
  val hello = CountDownLatch(1);@Volatile private var client: Socket? = null
  private val worker = Thread {
   try { client = listener.accept();client!!.getInputStream().use { input ->
    if (input.read() >= 0) hello.countDown();while (input.read() >= 0) { }
   } } catch (_: Exception) { }
  }.apply { isDaemon = true;start() }
  override fun close() { listener.close();client?.close();worker.join(3000);assertFalse(worker.isAlive) }
 }
 private fun text(peer: StallPeer) = """[qeli]
server = 127.0.0.1:${peer.port}
proto = tcp
user = permission-fixture
pass = fixture
mode = fake-tls
bind_static = false
reconnect = false
timeout = 30
"""
 private fun launch(peer: StallPeer): ActivityScenario<MainActivity> {
  val raw = JSONObject().put("active", 0).put("profiles", JSONArray().put(
   JSONObject().put("name", "permission fixture").put("cfg", text(peer)))).toString()
  assertTrue(ProfileStore.open(context).edit().putString("profiles_json", raw).commit())
  return ActivityScenario.launch<MainActivity>(Intent(context, MainActivity::class.java)).also { scenario = it }
 }
 private fun call(activity: MainActivity, name: String) = MainActivity::class.java.getDeclaredMethod(name)
  .apply { isAccessible = true }.invoke(activity)
 private fun grantNotification(activity: MainActivity) {
  // Registration order: VPN #0, import #1, QR #2, notification #3; use actual registry.
  val registry = activity.activityResultRegistry
  val codes = androidx.activity.result.ActivityResultRegistry::class.java.getDeclaredField("mKeyToRc")
   .apply { isAccessible = true }.get(registry) as Map<*, *>
  val code = codes["activity_rq#3"] as Int
  assertTrue(registry.dispatchResult(code, true))
 }
 private fun awaitNotification(activity: MainActivity, peer: StallPeer) {
    // Seed the pending phase without a modal PermissionController window. The actual
    // Activity/registry save-restore and ViewModel retention remain framework operations.
    val old = MainActivity::class.java.declaredFields.firstOrNull { it.name == "pendingConnect" }
    if (old != null) old.apply { isAccessible = true }.setBoolean(activity, true)
    else {
     val request = call(activity, "getConnectRequest")!!
     val config = com.qeli.model.VpnConfig.parse(text(peer)).also { it.validate() }
     request.javaClass.getDeclaredMethod("begin", com.qeli.model.VpnConfig::class.java)
      .apply { isAccessible = true }.invoke(request, config)
     val kind = Class.forName("com.qeli.VpnConnectRequest\$Permission")
     request.javaClass.getDeclaredMethod("awaitPermission", kind).apply { isAccessible = true }
      .invoke(request, requireNotNull(kind.enumConstants).first { it.toString() == "NOTIFICATION" })
    }
    val registry = activity.activityResultRegistry
    @Suppress("UNCHECKED_CAST")
    val launched = androidx.activity.result.ActivityResultRegistry::class.java.getDeclaredField("mLaunchedKeys")
     .apply { isAccessible = true }.get(registry) as MutableList<String>
    launched.add("activity_rq#3")
  call(activity, "setConnectingState")
 }
 @Test fun cancelledPermissionCannotResurrectVpn() {
  StallPeer().use { peer ->
   val activity = launch(peer)
   activity.onActivity { owner -> awaitNotification(owner, peer);call(owner, "disconnect") }
   await("cancel did not finish before delayed callback") {
    service() == null && VpnServiceImpl.liveStatus == VpnServiceImpl.STATUS_DISCONNECTED
   }
   activity.onActivity { grantNotification(it) }
   assertFalse("late permission result started cancelled VPN", peer.hello.await(3, TimeUnit.SECONDS))
   await("cancel did not leave service stopped") { service() == null }
   assertFalse(context.getSharedPreferences(MainActivity.PREFS_STATE, Context.MODE_PRIVATE)
    .getBoolean(MainActivity.PREF_CONNECTION_DESIRED, true))
  }
 }
 @Test fun permissionUsesOriginallyValidatedProfile() {
  StallPeer().use { original -> StallPeer().use { replacement ->
   launch(original).onActivity { activity ->
    awaitNotification(activity, original)
    val profiles = MainActivity::class.java.getDeclaredField("profiles").apply { isAccessible = true }.get(activity) as List<*>
    val profile = profiles[0]!!
    profile.javaClass.getDeclaredField("text").apply { isAccessible = true }.set(profile, text(replacement))
    grantNotification(activity)
   }
   val started = original.hello.await(6, TimeUnit.SECONDS)
   assertTrue("original profile not started; replacementHello=${replacement.hello.count == 0L}", started)
   assertFalse("different current profile was started", replacement.hello.await(250, TimeUnit.MILLISECONDS))
  } }
 }
 @Test fun permissionRequestSurvivesActivityRecreation() {
  StallPeer().use { peer ->
   val activity = launch(peer)
   activity.onActivity { owner ->
    awaitNotification(owner, peer)
   }
   activity.recreate()
   activity.onActivity { grantNotification(it) }
   assertTrue("recreated activity lost pending connect", peer.hello.await(6, TimeUnit.SECONDS))
  }
 }
}
