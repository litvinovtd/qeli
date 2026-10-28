# Generated from pre-R8 AndroidTest/runner references; instrumented Release only.
# Regenerate after AndroidTest/dependency changes; see qeli-android/README.md.
# Explicit reflection contract for the connection-log regression fixture.
-keepclassmembers,allowaccessmodification class com.qeli.VpnServiceImpl {
  private boolean checkKnownHost(java.lang.String, java.lang.String);
  private void broadcastLog(java.lang.String, java.lang.String);
  private java.lang.Object finishDiagnosticSession(boolean, kotlin.coroutines.Continuation);
  private java.util.concurrent.ExecutorService carrierDnsExecutor;
}
-keep,allowaccessmodification class androidx.activity.ComponentActivity {
  public androidx.activity.result.ActivityResultRegistry getActivityResultRegistry();
}
-keep,allowaccessmodification class androidx.activity.result.ActivityResultRegistry {
  public boolean dispatchResult(int,java.lang.Object);
}
-keep,allowaccessmodification @interface androidx.annotation.ChecksSdkIntAtLeast {
  public int api();
  public int extension();
}
-keep,allowaccessmodification @interface androidx.annotation.GuardedBy {
  public java.lang.String value();
}
-keep,allowaccessmodification @interface androidx.annotation.NonNull {
}
-keep,allowaccessmodification @interface androidx.annotation.Nullable {
}
-keep,allowaccessmodification @interface androidx.annotation.RequiresApi {
  public int value();
}
-keep,allowaccessmodification @interface androidx.annotation.RestrictTo {
  public androidx.annotation.RestrictTo$Scope[] value();
}
-keep,allowaccessmodification enum androidx.annotation.RestrictTo$Scope {
  androidx.annotation.RestrictTo$Scope LIBRARY;
  androidx.annotation.RestrictTo$Scope LIBRARY_GROUP;
}
-keep,allowaccessmodification @interface androidx.annotation.VisibleForTesting {
}
-keep,allowaccessmodification class androidx.concurrent.futures.AbstractResolvableFuture {
  public void addListener(java.lang.Runnable,java.util.concurrent.Executor);
  public boolean cancel(boolean);
  public java.lang.Object get();
  public java.lang.Object get(long,java.util.concurrent.TimeUnit);
  static java.lang.Object getUninterruptibly(java.util.concurrent.Future);
  public boolean isCancelled();
  public boolean isDone();
}
-keep,allowaccessmodification class androidx.concurrent.futures.CallbackToFutureAdapter {
  public static com.google.common.util.concurrent.ListenableFuture getFuture(androidx.concurrent.futures.CallbackToFutureAdapter$Resolver);
}
-keep,allowaccessmodification class androidx.concurrent.futures.CallbackToFutureAdapter$Completer {
  public boolean set(java.lang.Object);
  public boolean setException(java.lang.Throwable);
}
-keep,allowaccessmodification interface androidx.concurrent.futures.CallbackToFutureAdapter$Resolver {
  public java.lang.Object attachCompleter(androidx.concurrent.futures.CallbackToFutureAdapter$Completer);
}
-keep,allowaccessmodification enum androidx.concurrent.futures.DirectExecutor {
  androidx.concurrent.futures.DirectExecutor INSTANCE;
}
-keep,allowaccessmodification class androidx.concurrent.futures.ResolvableFuture {
  public static androidx.concurrent.futures.ResolvableFuture create();
  public boolean set(java.lang.Object);
  public boolean setException(java.lang.Throwable);
}
-keep,allowaccessmodification enum androidx.lifecycle.Lifecycle$State {
  public static androidx.lifecycle.Lifecycle$State[] values();
  androidx.lifecycle.Lifecycle$State CREATED;
  androidx.lifecycle.Lifecycle$State DESTROYED;
  androidx.lifecycle.Lifecycle$State RESUMED;
  androidx.lifecycle.Lifecycle$State STARTED;
}
-keep,allowaccessmodification class androidx.tracing.Trace {
  public static void beginSection(java.lang.String);
  public static void endSection();
  public static void forceEnableAppTracing();
}
-keep,allowaccessmodification interface com.google.common.util.concurrent.ListenableFuture {
  public void addListener(java.lang.Runnable,java.util.concurrent.Executor);
}
-keep,allowaccessmodification @interface com.google.errorprone.annotations.CanIgnoreReturnValue {
}
-keep,allowaccessmodification @interface com.google.errorprone.annotations.InlineMe {
  public java.lang.String replacement();
}
-keep,allowaccessmodification @interface com.google.errorprone.annotations.MustBeClosed {
}
-keep,allowaccessmodification class com.qeli.BoundedInput {
  public static byte[] read$default(com.qeli.BoundedInput,java.io.InputStream,int,java.lang.String,int,java.lang.Object);
  com.qeli.BoundedInput INSTANCE;
}
-keep,allowaccessmodification class com.qeli.DiagnosticLogEntry {
  public <init>(long,java.lang.String,java.lang.String,java.lang.String);
  public java.lang.String getMessage();
}
-keep,allowaccessmodification class com.qeli.DiagnosticLogStore {
  public static com.qeli.DiagnosticLogEntry append$app$default(com.qeli.DiagnosticLogStore,java.io.File,java.lang.String,java.lang.String,java.lang.String,long,int,long,int,java.lang.Object);
  public void clear$app(java.io.File);
  public static java.util.List read$app$default(com.qeli.DiagnosticLogStore,java.io.File,int,long,int,java.lang.Object);
  com.qeli.DiagnosticLogStore INSTANCE;
}
-keep,allowaccessmodification class com.qeli.MainActivity {
  com.qeli.MainActivity$Companion Companion;
}
-keep,allowaccessmodification class com.qeli.MainActivity$Companion {
  public boolean getUiVisible$app();
}
-keep,allowaccessmodification class com.qeli.ProfileStore {
  public java.lang.String activeProfileConfigText(android.content.Context);
  public void clearConnectionConfig(android.content.Context);
  public java.lang.String connectionConfigText(android.content.Context);
  public com.qeli.ProfileStore$SecureStore open(android.content.Context);
  public void saveConnectionConfig(android.content.Context,java.lang.String);
  com.qeli.ProfileStore INSTANCE;
}
-keep,allowaccessmodification class com.qeli.ProfileStore$SecureStore {
  public <init>(android.content.Context,java.lang.String,java.lang.String);
  public com.qeli.ProfileStore$SecureStore$Editor edit();
  public java.lang.String getString(java.lang.String,java.lang.String);
  public static com.qeli.ProfileStore$SecureStore$Version putStringIfVersion$default(com.qeli.ProfileStore$SecureStore,java.lang.String,com.qeli.ProfileStore$SecureStore$Version,java.lang.String,boolean,int,java.lang.Object);
  public com.qeli.ProfileStore$SecureStore$Version putStringIfVersion(java.lang.String,com.qeli.ProfileStore$SecureStore$Version,java.lang.String,boolean);
  public com.qeli.ProfileStore$SecureStore$Version version(java.lang.String);
}
-keep,allowaccessmodification class com.qeli.ProfileStore$SecureStore$Editor {
  public boolean commit();
  public com.qeli.ProfileStore$SecureStore$Editor putString(java.lang.String,java.lang.String);
}
-keep,allowaccessmodification class com.qeli.ProfileStore$SecureStore$StaleVersionException {
}
-keep,allowaccessmodification class com.qeli.ProfileStore$SecureStore$Version {
  public java.lang.Object getEncrypted();
  public boolean getPresent();
}
-keep,allowaccessmodification class com.qeli.R$string {
  int allow_lan;
  int loading_apps;
}
-keep,allowaccessmodification class com.qeli.StrictUtf8Kt {
  public static java.lang.String decodeUtf8Strict(byte[]);
}
-keep,allowaccessmodification class com.qeli.TransportCore {
  public void close();
  public static java.util.List drainEvents$default(com.qeli.TransportCore,int,int,java.lang.Object);
  public static void networkPlanResult$default(com.qeli.TransportCore,long,boolean,java.lang.String,int,java.lang.Object);
  public com.qeli.TransportCoreEvent pollEvent();
  public static int runTransport$default(com.qeli.TransportCore,java.util.List,java.util.List,int,java.lang.Object);
  public void setTunFd(long,int);
  public void start();
  public int state();
  public void stop();
  com.qeli.TransportCore$Companion Companion;
}
-keep,allowaccessmodification class com.qeli.TransportCore$Companion {
  public static com.qeli.TransportCore create$default(com.qeli.TransportCore$Companion,java.lang.String,byte[],long,int,int,java.lang.Object);
}
-keep,allowaccessmodification class com.qeli.TransportCoreEvent {
  public int getKind();
}
-keep,allowaccessmodification class com.qeli.TransportCoreEventCodec {
  public com.qeli.TransportCoreNetworkPlan decodeNetworkPlan(com.qeli.TransportCoreEvent);
  com.qeli.TransportCoreEventCodec INSTANCE;
}
-keep,allowaccessmodification class com.qeli.TransportCoreNetworkPlan {
  public long getGeneration();
}
-keep,allowaccessmodification class com.qeli.TrustedWifiPolicy {
  public java.lang.String normalizeObservedSsid(java.lang.String);
  com.qeli.TrustedWifiPolicy INSTANCE;
}
-keep,allowaccessmodification class com.qeli.VpnConnectRequest {
  public void awaitPermission(com.qeli.VpnConnectRequest$Permission);
  public boolean begin(com.qeli.model.VpnConfig);
  public boolean finishPermission(com.qeli.VpnConnectRequest$Permission,boolean);
  public boolean getHasOutstandingResult();
  public boolean isActive();
  public com.qeli.model.VpnConfig takeConfiguration();
}
-keep,allowaccessmodification enum com.qeli.VpnConnectRequest$Permission {
  com.qeli.VpnConnectRequest$Permission NOTIFICATION;
}
-keep,allowaccessmodification class com.qeli.VpnRecoveryService {
}
-keep,allowaccessmodification class com.qeli.VpnServiceImpl {
  public <init>();
  com.qeli.VpnServiceImpl$Companion Companion;
  com.qeli.model.LiveConnectionProperties liveConnectionProperties;
  java.lang.String liveIp;
  boolean liveLockdown;
  java.lang.String liveStatus;
  java.lang.String liveTrustedSsid;
}
-keep,allowaccessmodification class com.qeli.VpnServiceImpl$Companion {
  public java.lang.String getDebugTunSelfTestResult$app();
  public void setDebugTunSelfTestResult$app(java.lang.String);
}
-keep,allowaccessmodification class com.qeli.crypto.BackupCrypto {
  public java.lang.String decrypt(byte[],java.lang.String);
  com.qeli.crypto.BackupCrypto INSTANCE;
}
-keep,allowaccessmodification class com.qeli.model.LiveConnectionProperties {
}
-keep,allowaccessmodification class com.qeli.model.VpnConfig {
  public <init>(java.lang.String,int,java.lang.String,long,boolean,int,long,long,java.lang.String,java.lang.String,java.lang.String,boolean,boolean,int,boolean,java.lang.String,boolean,java.lang.String,java.lang.String,boolean,java.util.List,java.util.List,boolean,boolean,boolean,boolean,java.util.List,java.lang.String,java.lang.String,java.lang.String,java.lang.String,boolean,int,int,int,boolean,java.lang.String,java.lang.String,boolean,int,int,boolean,long,int,long,boolean,long,long,long,int,int,int,boolean,int,java.lang.String,java.util.List,java.lang.String,java.lang.String,java.lang.String,java.util.List,java.util.Map,java.util.List,java.util.List,java.util.List,java.lang.String,java.util.List,int,int,int,kotlin.jvm.internal.DefaultConstructorMarker);
  public static com.qeli.model.VpnConfig copy$default(com.qeli.model.VpnConfig,java.lang.String,int,java.lang.String,long,boolean,int,long,long,java.lang.String,java.lang.String,java.lang.String,boolean,boolean,int,boolean,java.lang.String,boolean,java.lang.String,java.lang.String,boolean,java.util.List,java.util.List,boolean,boolean,boolean,boolean,java.util.List,java.lang.String,java.lang.String,java.lang.String,java.lang.String,boolean,int,int,int,boolean,java.lang.String,java.lang.String,boolean,int,int,boolean,long,int,long,boolean,long,long,long,int,int,int,boolean,int,java.lang.String,java.util.List,java.lang.String,java.lang.String,java.lang.String,java.util.List,java.util.Map,java.util.List,java.util.List,java.util.List,java.lang.String,java.util.List,int,int,int,java.lang.Object);
  public java.util.List getApps();
  public java.lang.String getAppsMode();
  public boolean getMtuProbe();
  public int getPort();
  public java.lang.String getServerAddress();
  public static java.lang.String toIni$default(com.qeli.model.VpnConfig,java.lang.String,int,java.lang.Object);
  public java.lang.String toIni(java.lang.String);
  public static java.lang.String toTransportCoreIni$default(com.qeli.model.VpnConfig,java.lang.String,int,java.lang.Object);
  public void validate();
  com.qeli.model.VpnConfig$Companion Companion;
}
-keep,allowaccessmodification class com.qeli.model.VpnConfig$Companion {
  public com.qeli.model.VpnConfig fromIni(java.lang.String);
  public com.qeli.model.VpnConfig fromQeliUri(java.lang.String);
  public com.qeli.model.VpnConfig parse(java.lang.String);
}
-keep,allowaccessmodification @interface kotlin.Deprecated {
  public java.lang.String message();
  public kotlin.ReplaceWith replaceWith();
}
-keep,allowaccessmodification interface kotlin.Lazy {
  public java.lang.Object getValue();
}
-keep,allowaccessmodification class kotlin.LazyKt {
}
-keep,allowaccessmodification class kotlin.LazyKt__LazyJVMKt {
  public static kotlin.Lazy lazy(kotlin.jvm.functions.Function0);
}
-keep,allowaccessmodification @interface kotlin.Metadata {
  public java.lang.String[] d1();
  public java.lang.String[] d2();
  public int k();
  public int[] mv();
  public int xi();
}
-keep,allowaccessmodification class kotlin.Pair {
  public java.lang.Object component1();
  public java.lang.Object component2();
}
-keep,allowaccessmodification class kotlin.Result {
  public static java.lang.Object constructor-impl(java.lang.Object);
  public static java.lang.Throwable exceptionOrNull-impl(java.lang.Object);
  public static boolean isFailure-impl(java.lang.Object);
  kotlin.Result$Companion Companion;
}
-keep,allowaccessmodification class kotlin.Result$Companion {
}
-keep,allowaccessmodification class kotlin.ResultKt {
  public static java.lang.Object createFailure(java.lang.Throwable);
  public static void throwOnFailure(java.lang.Object);
}
-keep,allowaccessmodification class kotlin.TuplesKt {
  public static kotlin.Pair to(java.lang.Object,java.lang.Object);
}
-keep,allowaccessmodification class kotlin.Unit {
  kotlin.Unit INSTANCE;
}
-keep,allowaccessmodification class kotlin.collections.ArraysKt {
}
-keep,allowaccessmodification class kotlin.collections.ArraysKt___ArraysJvmKt {
  public static byte[] copyOfRange(byte[],int,int);
  public static void fill$default(byte[],byte,int,int,int,java.lang.Object);
  public static byte[] plus(byte[],byte[]);
}
-keep,allowaccessmodification class kotlin.collections.ArraysKt___ArraysKt {
  public static int getLastIndex(byte[]);
  public static byte last(byte[]);
  public static byte[] reversedArray(byte[]);
}
-keep,allowaccessmodification class kotlin.collections.CollectionsKt {
}
-keep,allowaccessmodification class kotlin.collections.CollectionsKt__CollectionsJVMKt {
  public static java.util.List listOf(java.lang.Object);
}
-keep,allowaccessmodification class kotlin.collections.CollectionsKt__CollectionsKt {
  public static java.util.List emptyList();
  public static java.util.List listOf(java.lang.Object[]);
}
-keep,allowaccessmodification class kotlin.collections.CollectionsKt__IterablesKt {
  public static int collectionSizeOrDefault(java.lang.Iterable,int);
}
-keep,allowaccessmodification class kotlin.collections.CollectionsKt__MutableCollectionsKt {
  public static boolean addAll(java.util.Collection,java.lang.Iterable);
}
-keep,allowaccessmodification class kotlin.collections.CollectionsKt___CollectionsKt {
  public static boolean contains(java.lang.Iterable,java.lang.Object);
  public static java.util.List plus(java.util.Collection,java.lang.Iterable);
  public static java.lang.Object single(java.util.List);
  public static java.util.Set toSet(java.lang.Iterable);
}
-keep,allowaccessmodification class kotlin.collections.IntIterator {
  public int nextInt();
}
-keep,allowaccessmodification class kotlin.collections.MapsKt {
}
-keep,allowaccessmodification class kotlin.collections.MapsKt__MapsKt {
  public static java.lang.Object getValue(java.util.Map,java.lang.Object);
  public static java.util.Map toMap(java.util.Map);
}
-keep,allowaccessmodification class kotlin.collections.SetsKt {
}
-keep,allowaccessmodification class kotlin.collections.SetsKt__SetsKt {
  public static java.util.Set setOf(java.lang.Object[]);
}
-keep,allowaccessmodification class kotlin.concurrent.ThreadsKt {
  public static java.lang.Thread thread$default(boolean,boolean,java.lang.ClassLoader,java.lang.String,int,kotlin.jvm.functions.Function0,int,java.lang.Object);
}
-keep,allowaccessmodification interface kotlin.coroutines.Continuation {
  public kotlin.coroutines.CoroutineContext getContext();
  public void resumeWith(java.lang.Object);
}
-keep,allowaccessmodification class kotlin.coroutines.ContinuationKt {
  public static kotlin.coroutines.Continuation createCoroutine(kotlin.jvm.functions.Function1,kotlin.coroutines.Continuation);
}
-keep,allowaccessmodification interface kotlin.coroutines.CoroutineContext {
}
-keep,allowaccessmodification class kotlin.coroutines.EmptyCoroutineContext {
  kotlin.coroutines.EmptyCoroutineContext INSTANCE;
}
-keep,allowaccessmodification class kotlin.coroutines.intrinsics.IntrinsicsKt {
}
-keep,allowaccessmodification class kotlin.coroutines.intrinsics.IntrinsicsKt__IntrinsicsJvmKt {
  public static kotlin.coroutines.Continuation intercepted(kotlin.coroutines.Continuation);
}
-keep,allowaccessmodification class kotlin.coroutines.intrinsics.IntrinsicsKt__IntrinsicsKt {
  public static java.lang.Object getCOROUTINE_SUSPENDED();
}
-keep,allowaccessmodification class kotlin.coroutines.jvm.internal.ContinuationImpl {
  public <init>(kotlin.coroutines.Continuation);
}
-keep,allowaccessmodification @interface kotlin.coroutines.jvm.internal.DebugMetadata {
  public java.lang.String c();
  public java.lang.String f();
  public int[] i();
  public int[] l();
  public java.lang.String m();
  public java.lang.String[] n();
  public java.lang.String[] s();
}
-keep,allowaccessmodification class kotlin.coroutines.jvm.internal.DebugProbesKt {
  public static void probeCoroutineSuspended(kotlin.coroutines.Continuation);
}
-keep,allowaccessmodification interface kotlin.coroutines.jvm.internal.SuspendFunction {
}
-keep,allowaccessmodification class kotlin.coroutines.jvm.internal.SuspendLambda {
  public <init>(int,kotlin.coroutines.Continuation);
}
-keep,allowaccessmodification class kotlin.io.ByteStreamsKt {
  public static byte[] readBytes(java.io.InputStream);
}
-keep,allowaccessmodification class kotlin.io.CloseableKt {
  public static void closeFinally(java.io.Closeable,java.lang.Throwable);
}
-keep,allowaccessmodification class kotlin.io.FilesKt {
}
-keep,allowaccessmodification class kotlin.io.FilesKt__FileReadWriteKt {
  public static byte[] readBytes(java.io.File);
}
-keep,allowaccessmodification class kotlin.io.FilesKt__UtilsKt {
  public static boolean deleteRecursively(java.io.File);
}
-keep,allowaccessmodification class kotlin.jdk7.AutoCloseableKt {
  public static void closeFinally(java.lang.AutoCloseable,java.lang.Throwable);
}
-keep,allowaccessmodification @interface kotlin.jvm.JvmName {
  public java.lang.String name();
}
-keep,allowaccessmodification @interface kotlin.jvm.JvmStatic {
}
-keep,allowaccessmodification interface kotlin.jvm.functions.Function0 {
  public java.lang.Object invoke();
}
-keep,allowaccessmodification interface kotlin.jvm.functions.Function1 {
  public java.lang.Object invoke(java.lang.Object);
}
-keep,allowaccessmodification interface kotlin.jvm.functions.Function2 {
  public java.lang.Object invoke(java.lang.Object,java.lang.Object);
}
-keep,allowaccessmodification class kotlin.jvm.internal.CallableReference {
  java.lang.Object receiver;
}
-keep,allowaccessmodification class kotlin.jvm.internal.DefaultConstructorMarker {
}
-keep,allowaccessmodification class kotlin.jvm.internal.FunctionReferenceImpl {
  public <init>(int,java.lang.Object,java.lang.Class,java.lang.String,java.lang.String,int);
}
-keep,allowaccessmodification class kotlin.jvm.internal.Intrinsics {
  public static boolean areEqual(java.lang.Object,java.lang.Object);
  public static void checkNotNull(java.lang.Object);
  public static void checkNotNull(java.lang.Object,java.lang.String);
  public static void checkNotNullExpressionValue(java.lang.Object,java.lang.String);
  public static void checkNotNullParameter(java.lang.Object,java.lang.String);
  public static void throwUninitializedPropertyAccessException(java.lang.String);
}
-keep,allowaccessmodification class kotlin.jvm.internal.Lambda {
  public <init>(int);
}
-keep,allowaccessmodification class kotlin.jvm.internal.Ref$BooleanRef {
  public <init>();
  boolean element;
}
-keep,allowaccessmodification class kotlin.jvm.internal.Ref$IntRef {
  public <init>();
  int element;
}
-keep,allowaccessmodification class kotlin.jvm.internal.Ref$ObjectRef {
  public <init>();
  java.lang.Object element;
}
-keep,allowaccessmodification @interface kotlin.jvm.internal.SourceDebugExtension {
  public java.lang.String[] value();
}
-keep,allowaccessmodification class kotlin.jvm.internal.StringCompanionObject {
  kotlin.jvm.internal.StringCompanionObject INSTANCE;
}
-keep,allowaccessmodification class kotlin.jvm.internal.TypeIntrinsics {
  public static java.util.List asMutableList(java.lang.Object);
}
-keep,allowaccessmodification class kotlin.ranges.IntRange {
}
-keep,allowaccessmodification class kotlin.ranges.RangesKt {
}
-keep,allowaccessmodification class kotlin.ranges.RangesKt___RangesKt {
  public static kotlin.ranges.IntRange until(int,int);
}
-keep,allowaccessmodification interface kotlin.sequences.Sequence {
  public java.util.Iterator iterator();
}
-keep,allowaccessmodification class kotlin.sequences.SequencesKt {
}
-keep,allowaccessmodification class kotlin.sequences.SequencesKt__SequencesKt {
  public static kotlin.sequences.Sequence generateSequence(kotlin.jvm.functions.Function0);
}
-keep,allowaccessmodification class kotlin.text.Charsets {
  java.nio.charset.Charset UTF_8;
}
-keep,allowaccessmodification class kotlin.text.Regex {
  public <init>(java.lang.String);
  public boolean containsMatchIn(java.lang.CharSequence);
  public boolean matches(java.lang.CharSequence);
}
-keep,allowaccessmodification class kotlin.text.StringsKt {
}
-keep,allowaccessmodification class kotlin.text.StringsKt__StringsJVMKt {
  public static java.lang.String repeat(java.lang.CharSequence,int);
  public static boolean startsWith$default(java.lang.String,java.lang.String,boolean,int,java.lang.Object);
}
-keep,allowaccessmodification class kotlin.text.StringsKt__StringsKt {
  public static boolean contains$default(java.lang.CharSequence,char,boolean,int,java.lang.Object);
  public static boolean contains$default(java.lang.CharSequence,java.lang.CharSequence,boolean,int,java.lang.Object);
  public static boolean isBlank(java.lang.CharSequence);
  public static java.util.List split$default(java.lang.CharSequence,java.lang.String[],boolean,int,int,java.lang.Object);
}
-keep,allowaccessmodification class kotlin.time.Duration {
  kotlin.time.Duration$Companion Companion;
}
-keep,allowaccessmodification class kotlin.time.Duration$Companion {
}
-keep,allowaccessmodification class kotlin.time.DurationKt {
  public static long toDuration(int,kotlin.time.DurationUnit);
}
-keep,allowaccessmodification enum kotlin.time.DurationUnit {
  kotlin.time.DurationUnit SECONDS;
}
-keep,allowaccessmodification class kotlinx.coroutines.BuildersKt {
  public static kotlinx.coroutines.Deferred async(kotlinx.coroutines.CoroutineScope,kotlin.coroutines.CoroutineContext,kotlinx.coroutines.CoroutineStart,kotlin.jvm.functions.Function2);
  public static java.lang.Object runBlocking(kotlin.coroutines.CoroutineContext,kotlin.jvm.functions.Function2);
}
-keep,allowaccessmodification interface kotlinx.coroutines.CancellableContinuation {
  public void invokeOnCancellation(kotlin.jvm.functions.Function1);
  public void resume(java.lang.Object,kotlin.jvm.functions.Function1);
}
-keep,allowaccessmodification class kotlinx.coroutines.CancellableContinuation$DefaultImpls {
  public static boolean cancel$default(kotlinx.coroutines.CancellableContinuation,java.lang.Throwable,int,java.lang.Object);
}
-keep,allowaccessmodification class kotlinx.coroutines.CancellableContinuationImpl {
  public <init>(kotlin.coroutines.Continuation,int);
  public java.lang.Object getResult();
  public void initCancellability();
}
-keep,allowaccessmodification class kotlinx.coroutines.CoroutineDispatcher {
}
-keep,allowaccessmodification interface kotlinx.coroutines.CoroutineScope {
  public kotlin.coroutines.CoroutineContext getCoroutineContext();
}
-keep,allowaccessmodification enum kotlinx.coroutines.CoroutineStart {
  kotlinx.coroutines.CoroutineStart DEFAULT;
  kotlinx.coroutines.CoroutineStart UNDISPATCHED;
}
-keep,allowaccessmodification interface kotlinx.coroutines.Deferred {
  public java.lang.Object await(kotlin.coroutines.Continuation);
}
-keep,allowaccessmodification class kotlinx.coroutines.Dispatchers {
  public static kotlinx.coroutines.MainCoroutineDispatcher getMain();
  public static kotlinx.coroutines.CoroutineDispatcher getUnconfined();
}
-keep,allowaccessmodification class kotlinx.coroutines.ExecutorsKt {
  public static kotlinx.coroutines.CoroutineDispatcher from(java.util.concurrent.Executor);
}
-keep,allowaccessmodification interface kotlinx.coroutines.Job {
}
-keep,allowaccessmodification class kotlinx.coroutines.Job$DefaultImpls {
  public static void cancel$default(kotlinx.coroutines.Job,java.util.concurrent.CancellationException,int,java.lang.Object);
}
-keep,allowaccessmodification class kotlinx.coroutines.MainCoroutineDispatcher {
}
-keep,allowaccessmodification class kotlinx.coroutines.TimeoutKt {
  public static java.lang.Object withTimeout-KLykuaI(long,kotlin.jvm.functions.Function2,kotlin.coroutines.Continuation);
}
-keep,allowaccessmodification @interface org.jetbrains.annotations.NotNull {
}
-keep,allowaccessmodification @interface org.jetbrains.annotations.Nullable {
}
-keeppackagenames androidx.concurrent.futures
