"""Production app packager with real files/tar and controlled build/sign tools.

No .NET/Rust compilation, actual signature or Apple runtime qualification.
"""
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import unittest


class AppSignerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="qeli-app-signer-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.project = self.root / "qeli-mac"
        (self.project / "QeliMac/native").mkdir(parents=True)
        (self.project / "QeliMac/native/libqeli.dylib").write_bytes(b"controlled native")
        (self.project / "LICENSE").write_text("fixture license")
        (self.project / "Info.plist.in").write_text("<plist>__ARCH__</plist>")
        source = Path(os.environ.get("QELI_MAC_APP_BASELINE", Path(__file__).resolve().parents[1] / "qeli-mac/build_app.sh"))
        (self.project / "build_app.sh").write_bytes(source.read_bytes().replace(b"\r\n", b"\n"))
        self.tools = self.root / "tools"; self.tools.mkdir()
        self.events = self.root / "events"
        self.bash = os.environ.get("QELI_TEST_BASH") or (
            "C:/Program Files/Git/bin/bash.exe" if os.name == "nt" else shutil.which("bash"))
        if not self.bash:raise RuntimeError("bash is required for package admission tests")
        self.posix = subprocess.check_output([self.bash, "-c", 'cd "$1" && pwd -P', "fixture", self.root.as_posix()], text=True).strip()
        self.tool("uname", "echo Linux")
        self.tool("python3", 'echo "legal $*" >> "$QELI_TEST_EVENTS"')
        self.tool("tar", 'echo "tar $*" >> "$QELI_TEST_EVENTS"\nexec /usr/bin/tar "$@"')
        self.tool("dotnet", r"""echo "dotnet $*" >> "$QELI_TEST_EVENTS"
if [[ "$1" == publish ]]; then
  while [[ "$#" -gt 0 ]]; do
    if [[ "$1" == -o ]]; then out="$2"; break; fi
    shift
  done
  mkdir -p "$out/Legal/NativeRust/files/axum-core/0.5.6" "$out/Legal/DotNet"
  printf '#!/bin/sh\nexit 0\n' > "$out/QeliMac"
  printf 'newer host-only CI core' > "$out/libqeli.dylib"
  cp "$QELI_TEST_PROJECT/LICENSE" "$out/Legal/MPL-2.0.txt"
  printf 'dependency license' > "$out/Legal/NativeRust/files/axum-core/0.5.6/LICENSE"
elif [[ "$1" == run ]]; then
  for icon do :; done
  printf 'controlled icon' > "$icon"
fi""")
        subprocess.run([self.bash, "-c", 'chmod +x "$1/qeli-mac/build_app.sh"', "fixture", self.posix], check=True)

    def tool(self, name, body):
        (self.tools / name).write_text("#!/bin/bash\n" + body + "\n", encoding="utf8")
        subprocess.run([self.bash, "-c", 'chmod +x "$1"', "fixture", self.posix + "/tools/" + name], check=True)

    def signer(self, name, rc=0):
        self.tool(name, f'echo "{name} $*" >> "$QELI_TEST_EVENTS"\nexit {rc}')

    def invoke(self, arch="arm64", native_override=None):
        self.events.unlink(missing_ok=True)
        archive = self.project / ("dist/Qeli-macos-" + arch + ".tar.gz")
        archive.parent.mkdir(exist_ok=True)
        archive.write_bytes(b"old archive")
        marker = self.project / "dist/Qeli.app/old-marker"
        marker.parent.mkdir(exist_ok=True)
        marker.write_bytes(b"old bundle")
        env = dict(os.environ, QELI_TEST_EVENTS=self.posix + "/events",
                   QELI_TEST_PROJECT=self.posix + "/qeli-mac",
                   QELI_MAC_SIGN_IDENTITY="", QELI_MAC_HOST_PROFILE="",
                   QELI_MAC_EXTENSION_PROFILE="", QELI_MAC_NOTARY_PROFILE="")
        env.pop("QeliNativeCorePath", None)
        if native_override is not None:
            env["QeliNativeCorePath"] = native_override
        result = subprocess.run([self.bash, "-c",
            'export PATH="$1/tools:/usr/bin:/bin"; "$1/qeli-mac/build_app.sh" "$2"',
            "fixture", self.posix, arch], capture_output=True, text=True, env=env, timeout=30)
        events = self.events.read_text() if self.events.exists() else ""
        return result, events, archive, marker

    def test_missing_signer_refuses_before_build_and_keeps_outputs(self):
        for arch in ("arm64", "x86_64"):
            with self.subTest(arch=arch):
                r, events, archive, marker = self.invoke(arch)
                self.assertNotEqual(r.returncode, 0, r.stdout+r.stderr)
                self.assertEqual(events, "")
                self.assertEqual(archive.read_bytes(), b"old archive")
                self.assertEqual(marker.read_bytes(), b"old bundle")

    def test_missing_signer_precedes_native_bootstrap(self):
        (self.project / "QeliMac/native/libqeli.dylib").unlink()
        (self.root / "qeli").mkdir()
        script = self.project / "build_dylib.sh"
        script.write_text('#!/bin/bash\necho native >> "$QELI_TEST_EVENTS"\n')
        subprocess.run([self.bash, "-c", 'chmod +x "$1"', "fixture", self.posix+"/qeli-mac/build_dylib.sh"],check=True)
        r, events, _, _ = self.invoke()
        self.assertNotEqual(r.returncode,0,r.stdout+r.stderr)
        self.assertEqual(events,"")

    def successful(self, signer):
        self.signer(signer)
        for arch in ("arm64", "x86_64"):
            with self.subTest(arch=arch):
                r, events, archive, _ = self.invoke(arch)
                self.assertEqual(r.returncode,0,r.stdout+r.stderr)
                self.assertIn(signer+" ",events)
                self.assertLess(events.index(signer+" "),events.index("tar "))
                with tarfile.open(archive,"r:gz") as incoming:
                    self.assertIn("Qeli.app/Contents/MacOS/QeliMac",incoming.getnames())
                    self.assertFalse(any(n.startswith("Qeli.app/Contents/MacOS/Legal") for n in incoming.getnames()))
                    self.assertEqual(incoming.extractfile("Qeli.app/Contents/Resources/Legal/MPL-2.0.txt").read(), b"fixture license")
                    self.assertEqual(incoming.extractfile("Qeli.app/Contents/Resources/Legal/NativeRust/files/axum-core/0.5.6/LICENSE").read(), b"dependency license")
                    self.assertEqual(incoming.extractfile("Qeli.app/Contents/MacOS/libqeli.dylib").read(), b"controlled native")

    def test_selected_native_override_replaces_newer_publish_core(self):
        self.signer("codesign")
        (self.root / "selected-native.dylib").write_bytes(b"selected universal core")
        for arch in ("arm64", "x86_64"):
            with self.subTest(arch=arch):
                r, _, archive, _ = self.invoke(arch, self.posix + "/selected-native.dylib")
                self.assertEqual(r.returncode, 0, r.stdout+r.stderr)
                with tarfile.open(archive, "r:gz") as incoming:
                    self.assertEqual(incoming.extractfile("Qeli.app/Contents/MacOS/libqeli.dylib").read(), b"selected universal core")

    def test_missing_explicit_native_input_refuses_before_publish(self):
        self.signer("codesign")
        r, events, archive, marker = self.invoke(native_override=self.posix + "/missing-native.dylib")
        self.assertNotEqual(r.returncode, 0, r.stdout+r.stderr)
        self.assertEqual(events, "")
        self.assertEqual(archive.read_bytes(), b"old archive")
        self.assertEqual(marker.read_bytes(), b"old bundle")

    def test_codesign_path_signs_before_actual_tar_packaging(self):
        self.successful("codesign")

    def test_rcodesign_path_signs_before_actual_tar_packaging(self):
        self.successful("rcodesign")

    def test_codesign_is_preferred_when_both_are_available(self):
        self.signer("codesign");self.signer("rcodesign")
        r, events, _, _ = self.invoke()
        self.assertEqual(r.returncode,0,r.stdout+r.stderr)
        self.assertIn("codesign --force",events)
        self.assertNotIn("rcodesign ",events)

    def test_codesign_failure_keeps_previous_archive(self):
        self.signer("codesign",7)
        r,events,archive,_=self.invoke()
        self.assertNotEqual(r.returncode,0)
        self.assertNotIn("tar ",events)
        self.assertEqual(archive.read_bytes(),b"old archive")

    def test_rcodesign_failure_keeps_previous_archive(self):
        self.signer("rcodesign",7)
        r,events,archive,_=self.invoke()
        self.assertNotEqual(r.returncode,0)
        self.assertNotIn("tar ",events)
        self.assertEqual(archive.read_bytes(),b"old archive")

    def test_unknown_arch_refuses_before_any_build_tool(self):
        self.signer("codesign")
        r,events,archive,_=self.invoke("invalid")
        self.assertNotEqual(r.returncode,0)
        self.assertEqual(events,"")
        self.assertEqual(archive.read_bytes(),b"old archive")


if __name__ == "__main__":
    unittest.main()
