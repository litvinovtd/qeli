package com.qeli

/** Values come from the installed APK, never a separately maintained release literal. */
internal fun androidApplicationBuildLog(versionName: String, versionCode: Long, apiLevel: Int): String =
    "Qeli Android version=$versionName build=$versionCode api=$apiLevel"
