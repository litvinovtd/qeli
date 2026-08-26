# VpnConfig crosses the Binder boundary as java.io.Serializable. Its explicit
# serialVersionUID pins the schema; the instance fields must remain available to
# ObjectInputStream, but unrelated model code is free to shrink and obfuscate.
-keepnames class com.qeli.model.VpnConfig
-keepclassmembers,allowoptimization class com.qeli.model.VpnConfig {
    private static final long serialVersionUID;
    !static !transient <fields>;
}

# Rust exports name-based Java_com_qeli_TransportCore_native* JNI symbols.
# Preserve only that ABI surface; manifest components are retained by AGP.
-keep class com.qeli.TransportCore {
    native <methods>;
}

# Tink (pulled in by EncryptedSharedPreferences, which stores the profiles) is compiled
# against JSR-305 annotations that ship in a separate, compile-only artifact. They are
# CLASS-retention — absent at runtime by design and never loaded — but R8 still walks the
# references and fails the release build over them. Nothing is stripped that Tink needs;
# without this the release APK cannot be assembled at all (debug is unaffected: no R8).
-dontwarn javax.annotation.Nullable
-dontwarn javax.annotation.concurrent.GuardedBy
