#!/usr/bin/env python3
"""Rebuild the debug APK on .11 from the CURRENT local source (v0.5.6 + rsid
qeli:// import) and pull it into qeli-android/dist/app-debug.apk.

Pushes the repo's committed jniLibs/*.so (the realtls FFI core is unchanged this
cycle — rsid lives in Kotlin), syncs Kotlin/resources/gradle WITHOUT wiping
jniLibs, builds offline, then pulls the APK locally (rotating the previous one).
"""
import os, sys, posixpath, socket, time
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import paramiko

LOCAL = r"C:\Users\litvi\OneDrive\Documents\OpenCode\VPN_CLAUDE\qeli-android"
REMOTE = "/root/android-project"
HOST = ("10.66.116.11", "root", os.environ.get("QELI_LAB_PASS", ""))
# Build via the project's Gradle wrapper (version pinned in
# gradle/wrapper/gradle-wrapper.properties — currently 9.5.1). AGP 9 requires
# Gradle >= 9.4.1, so the old standalone /root/gradle-8.11.1 can no longer apply
# the android plugin. The wrapper distribution is cached on .11.
SYNC_EXT = (".kt", ".xml", ".kts", ".properties", ".pro", ".png", ".webp", ".json")
SKIP_DIRS = {"build", ".gradle", ".kotlin", "dist", ".idea", "jniLibs"}
SKIP_FILES = {"local.properties"}
DIST = os.path.join(LOCAL, "dist")

def conn():
    last = None
    for _ in range(4):
        try:
            sk = socket.create_connection((HOST[0], 22), timeout=20)
            c = paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            c.connect(HOST[0], username=HOST[1], password=HOST[2], sock=sk,
                      look_for_keys=False, allow_agent=False, timeout=20)
            return c
        except Exception as e:
            last = e; time.sleep(2)
    raise last

def sh(c, cmd, t=1200):
    i, o, e = c.exec_command(cmd, timeout=t)
    out = o.read().decode("utf-8", "replace") + e.read().decode("utf-8", "replace")
    return out.strip(), o.channel.recv_exit_status()

c = conn(); sf = c.open_sftp()

# 1. Push the repo's committed .so so .11 builds with the in-repo native core.
print("=== 1. push repo jniLibs/*.so -> .11 ===")
for abi in ("arm64-v8a", "x86_64"):
    lp = os.path.join(LOCAL, "app", "src", "main", "jniLibs", abi, "libqeli.so")
    rp = f"{REMOTE}/app/src/main/jniLibs/{abi}/libqeli.so"
    sh(c, f"mkdir -p {posixpath.dirname(rp)}")
    sf.put(lp, rp)
    print(f"  [push] {abi}/libqeli.so ({os.path.getsize(lp)} bytes)")

# 2. Sync Kotlin/resources/gradle in place (skip jniLibs so the .so stays).
print("=== 2. sync sources (preserving jniLibs) ===")
n = 0
for root, dirs, names in os.walk(LOCAL):
    dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
    for nm in names:
        if nm in SKIP_FILES or not nm.endswith(SYNC_EXT):
            continue
        full = os.path.join(root, nm)
        rel = os.path.relpath(full, LOCAL).replace(os.sep, "/")
        remote = posixpath.join(REMOTE, rel)
        sh(c, f"mkdir -p {posixpath.dirname(remote)}")
        sf.put(full, remote); n += 1
print(f"  [sync] {n} files")
print("  [versionName on .11]:",
      sh(c, f"grep -E 'versionCode|versionName' {REMOTE}/app/build.gradle.kts")[0])

# 3. Build (clear any stale gradle lock first; offline).
print("=== 3. ./gradlew assembleDebug --offline ===")
sh(c, "pkill -9 -f GradleDaemon 2>/dev/null; rm -rf /root/.gradle/caches/journal-1 2>/dev/null; true")
out, rc = sh(c, f"cd {REMOTE} && chmod +x gradlew && ./gradlew clean assembleDebug --offline --no-daemon "
                f"-Dorg.gradle.vfs.watch=false 2>&1", t=1200)
print("\n".join(out.splitlines()[-15:]))
if "BUILD SUCCESSFUL" not in out:
    print(f"[build] FAILED (rc={rc})"); c.close(); sys.exit(1)

apk = f"{REMOTE}/app/build/outputs/apk/debug/app-debug.apk"
print("[apk on .11]", sh(c, f"stat -c '%y %s bytes' {apk}")[0])
print("  [.so in apk]", sh(c, f"unzip -l {apk} | grep libqeli.so")[0])
# version from the built APK (if aapt is available)
aapt, _ = sh(c, "find /root/android-sdk/build-tools -name aapt 2>/dev/null | head -1")
if aapt:
    print("  [badging]", sh(c, f"{aapt} dump badging {apk} 2>/dev/null | grep -oE \"version(Code|Name)='[^']*'\" | tr '\\n' ' '")[0])

# 4. Pull into local dist/ (rotate the previous APK).
print("=== 4. pull APK -> local dist ===")
os.makedirs(DIST, exist_ok=True)
cur = os.path.join(DIST, "app-debug.apk")
if os.path.exists(cur):
    prev = os.path.join(DIST, "app-debug.prev.apk")
    if os.path.exists(prev):
        os.remove(prev)
    os.replace(cur, prev)
    print("  [rotate] app-debug.apk -> app-debug.prev.apk")
sf.get(apk, cur)
print(f"  [saved] {cur} ({os.path.getsize(cur)} bytes)")
sf.close(); c.close()
print("[done]")
