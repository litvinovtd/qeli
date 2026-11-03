# Q25-F186: Android active-profile index

1 October 2026. Base: b0ca3824. D08 remains **IN_PROGRESS**.

Three Android paths read the internal active index through JSONObject.optInt. A wrong-type value silently became zero; service and tile also reset out-of-range indexes to zero. A damaged store or backup with multiple profiles could therefore select the first server and its credentials without notice. JSON is only the profile-list/backup container; user configs remain INI.

ProfileStore.readActiveProfileIndex now checks type, integrality, overflow and range in one place. An absent field keeps legacy default zero; null, boolean, string, fractional and out-of-range values fail. Numeric 1, 1.0 and 1e0 are accepted when mathematically integral, because org.json may normalize their representation. Import and Activity load use this parser; service and tile receive no config on failure. Direct service reads now share Activity's 8 MiB and 256-profile bounds.

160 JVM tests passed, including four new index tests; assembleDebug, assembleDebugAndroidTest and git diff --check passed. Emulator instrumentation was not run because SSH to lab .11 was rejected. The iOS importer had a separate NSNumber.intValue conversion; its alignment remained the next D08 item and is not claimed here.
