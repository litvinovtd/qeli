# Keep VpnConfig serializable
-keep class com.qeli.model.** { *; }

# Keep service
-keep class com.qeli.VpnServiceImpl { *; }

# Tink (pulled in by EncryptedSharedPreferences, which stores the profiles) is compiled
# against JSR-305 annotations that ship in a separate, compile-only artifact. They are
# CLASS-retention — absent at runtime by design and never loaded — but R8 still walks the
# references and fails the release build over them. Nothing is stripped that Tink needs;
# without this the release APK cannot be assembled at all (debug is unaffected: no R8).
-dontwarn javax.annotation.Nullable
-dontwarn javax.annotation.concurrent.GuardedBy
