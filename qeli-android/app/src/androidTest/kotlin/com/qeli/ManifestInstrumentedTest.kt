package com.qeli

import android.content.ComponentName
import android.content.Context
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import android.os.Build
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class ManifestInstrumentedTest {
    private val context: Context = ApplicationProvider.getApplicationContext()
    @Test fun recoveryRecordIsPrivateSameProcessAndSpecialUseOnly() {
        val service = context.packageManager.getServiceInfo(
            ComponentName(context, VpnRecoveryService::class.java), PackageManager.GET_META_DATA,
        )
        assertFalse(service.exported)
        assertEquals(context.applicationInfo.processName, service.processName)
        assertEquals(0, service.flags and android.content.pm.ServiceInfo.FLAG_STOP_WITH_TASK)
        if (Build.VERSION.SDK_INT >= 34) {
            assertEquals(ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE, service.foregroundServiceType)
            assertTrue(context.packageManager.getProperty(
                "android.app.PROPERTY_SPECIAL_USE_FGS_SUBTYPE",
                ComponentName(context, VpnRecoveryService::class.java),
            ).string?.isNotBlank() == true)
        }
    }
    @Test fun vpnServiceHasThePlatformSpecialUseProperty() {
        assumeTrue(Build.VERSION.SDK_INT >= 34)
        val property = context.packageManager.getProperty(
            "android.app.PROPERTY_SPECIAL_USE_FGS_SUBTYPE",
            ComponentName(context, VpnServiceImpl::class.java),
        )
        assertTrue(property.isString)
        assertTrue(property.string?.isNotBlank() == true)
    }
    @Test fun systemCloudAndDeviceTransferExcludeAppState() {
        assumeTrue(Build.VERSION.SDK_INT >= 31)
        assertTrue(context.applicationInfo.flags and android.content.pm.ApplicationInfo.FLAG_ALLOW_BACKUP == 0)
        var resource = 0
        context.assets.openXmlResourceParser("AndroidManifest.xml").use { xml ->
            while (xml.eventType != org.xmlpull.v1.XmlPullParser.END_DOCUMENT) {
                if (xml.eventType == org.xmlpull.v1.XmlPullParser.START_TAG && xml.name == "application") {
                    resource = xml.getAttributeResourceValue(
                        "http://schemas.android.com/apk/res/android", "dataExtractionRules", 0,
                    )
                }
                xml.next()
            }
        }
        assertTrue(resource != 0)
        val exclusions = mutableMapOf<String, MutableSet<String>>()
        context.resources.getXml(resource).use { xml ->
            var section = ""
            while (xml.eventType != org.xmlpull.v1.XmlPullParser.END_DOCUMENT) {
                if (xml.eventType == org.xmlpull.v1.XmlPullParser.START_TAG) {
                    when (xml.name) {
                        "cloud-backup", "device-transfer" -> { section = xml.name; exclusions[section] = mutableSetOf() }
                        "exclude" -> {
                            assertEquals(".", xml.getAttributeValue(null, "path"))
                            exclusions.getValue(section).add(xml.getAttributeValue(null, "domain"))
                        }
                    }
                }
                xml.next()
            }
        }
        val domains = setOf("root", "file", "database", "sharedpref", "external", "device_root", "device_file", "device_database", "device_sharedpref")
        assertEquals(setOf("cloud-backup", "device-transfer"), exclusions.keys)
        exclusions.values.forEach { assertEquals(domains, it) }
    }
    @Test fun vpnServiceRemainsPrivateAndDeclaresItsForegroundTypes() {
        val service = context.packageManager.getServiceInfo(
            ComponentName(context, VpnServiceImpl::class.java), PackageManager.GET_META_DATA,
        )
        assertFalse(service.exported)
        assertEquals("android.permission.BIND_VPN_SERVICE", service.permission)
        if (Build.VERSION.SDK_INT >= 34) {
            assertTrue(service.foregroundServiceType and ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE != 0)
            assertTrue(service.foregroundServiceType and ServiceInfo.FOREGROUND_SERVICE_TYPE_LOCATION != 0)
        }
    }
}
