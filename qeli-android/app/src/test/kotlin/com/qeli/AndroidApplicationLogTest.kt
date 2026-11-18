package com.qeli

import org.junit.Assert.assertEquals
import org.junit.Test

class AndroidApplicationLogTest {
    @Test fun buildBannerUsesSuppliedApkVersionAndPlatform() {
        assertEquals("Qeli Android version=9.8.7-test build=12345 api=29",
            androidApplicationBuildLog("9.8.7-test", 12345, 29))
        assertEquals("Qeli Android version=1.2.3 build=4 api=28",
            androidApplicationBuildLog("1.2.3", 4, 28))
        assertEquals("Qeli Android version=1.2.3 build=4294967296 api=37",
            androidApplicationBuildLog("1.2.3", 4_294_967_296L, 37))
    }
}
