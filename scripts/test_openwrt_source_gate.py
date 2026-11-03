"""Real Git metadata/source admission and local archive integrity; no SDK build."""
import ast
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import openwrt_source_gate as gate


class SourceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="qeli-source-gate-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root/"qeli/src").mkdir(parents=True)
        (self.root/"qeli-openwrt").mkdir()
        self.cargo = self.root/"qeli/Cargo.toml"
        self.cargo.write_text('[package]\nname="probe"\nversion="0.8.2"\n')
        (self.root/"qeli/src/lib.rs").write_text("pub fn source() {}\n")
        self.git("init", "--quiet")
        self.commit()
        self.pin = self.git("rev-parse", "HEAD").strip()
        self.archive = self.root/"sdk-source.tar.zst"
        self.archive.write_bytes(b"mirror byte fixture\x00\r\n\x80")
        self.digest = hashlib.sha256(self.archive.read_bytes()).hexdigest()
        self.recipe = self.root/"qeli-openwrt/Makefile"
        self.recipe.write_text(f"PKG_VERSION:=0.8.2\nPKG_SOURCE_VERSION:={self.pin}\nPKG_MIRROR_HASH:={self.digest}\n")
        self.commit()

    def git(self, *args):
        # A detached auto-maintenance child can outlive `git commit` and race
        # TemporaryDirectory.cleanup. Fixtures own their entire repository and
        # never need maintenance, including when the caller enables it globally.
        return subprocess.check_output(["git", "-c", "core.autocrlf=false",
                                        "-c", "maintenance.auto=false", "-c", "gc.auto=0", *args],
                                       cwd=self.root, text=True).strip()

    def test_fixture_does_not_start_inherited_automatic_maintenance(self):
        config = self.root / "inherited.gitconfig"
        config.write_text("[maintenance]\n\tauto = true\n\tstrategy = incremental\n"
                          "[gc]\n\tauto = 1\n")
        trace = self.root / "git-trace.json"
        with patch.dict(os.environ, {"GIT_CONFIG_GLOBAL": str(config),
                                     "GIT_CONFIG_NOSYSTEM": "1",
                                     "GIT_TRACE2_EVENT": str(trace.resolve())}):
            for index in range(3):
                self.cargo.write_text(self.cargo.read_text() + f"\n# fixture {index}\n")
                self.commit()
        events = [json.loads(line) for line in trace.read_text().splitlines()]
        children = [event.get("argv", []) for event in events if event.get("event") == "child_start"]
        self.assertTrue(any(event.get("event") == "exit" for event in events))
        self.assertFalse([args for args in children if "maintenance" in args or "gc" in args], children)

    def commit(self):
        self.git("add", "qeli", "qeli-openwrt")
        self.git("-c", "user.name=Audit Fixture", "-c", "user.email=audit@localhost",
                 "commit", "--quiet", "-m", "fixture")

    def replace(self, name, value):
        text = self.recipe.read_text()
        lines = [name+":="+value if line.startswith(name+":=") else line for line in text.splitlines()]
        self.recipe.write_text("\n".join(lines)+"\n")
        self.commit()

    def check(self, archive=None):
        return gate.check_openwrt_source(self.root, self.archive if archive is None else archive, lambda _: None)

    def test_older_commit_with_identical_crate_and_actual_hash_passes(self):
        self.assertNotEqual(self.pin, self.git("rev-parse", "HEAD"))
        self.assertEqual(self.check(), [])

    def test_archive_path_with_spaces_and_binary_CR_bytes_passes(self):
        other = self.root/"source bytes.tar.zst";other.write_bytes(self.archive.read_bytes())
        self.assertEqual(self.check(other), [])

    def test_missing_or_empty_archive_is_fatal(self):
        self.assertTrue(gate.check_openwrt_source(self.root, None, lambda _: None))
        self.assertTrue(self.check(self.root/"absent.tar.zst"))
        self.archive.write_bytes(b"");self.assertTrue(self.check())

    def test_well_formed_but_wrong_hash_is_fatal(self):
        self.archive.write_bytes(b"different bytes");self.assertTrue(self.check())

    def test_placeholder_skip_and_malformed_hashes_are_fatal(self):
        for value in ("0"*64, "skip", "f"*63, self.digest.upper(), "$(HASH)"):
            with self.subTest(value=value):
                self.replace("PKG_MIRROR_HASH",value);self.assertTrue(self.check())

    def test_mutable_tag_branch_and_HEAD_refs_are_fatal(self):
        self.git("tag","source-tag",self.pin)
        self.git("branch","source-branch",self.pin)
        for value in ("HEAD", "source-tag", "source-branch", self.pin[:12], "0"*40):
            with self.subTest(value=value):
                self.replace("PKG_SOURCE_VERSION",value);self.assertTrue(self.check())

    def test_full_annotated_tag_object_SHA_is_fatal(self):
        self.git("-c","user.name=Audit Fixture","-c","user.email=audit@localhost",
                 "tag","-a","annotated",self.pin,"-m","source")
        self.replace("PKG_SOURCE_VERSION",self.git("rev-parse","annotated"))
        self.assertTrue(self.check())

    def test_changed_crate_tree_is_fatal(self):
        (self.root/"qeli/src/lib.rs").write_text("pub fn changed() {}\n");self.commit()
        self.assertTrue(self.check())

    def test_duplicate_or_qualified_assignment_is_fatal(self):
        original=self.recipe.read_text()
        for extra in ("PKG_SOURCE_VERSION:=HEAD", "override export PKG_SOURCE_VERSION:=HEAD",
                      "PKG_MIRROR_HASH=skip", "define PKG_SOURCE_VERSION\nHEAD\nendef",
                      "$(eval PKG_SOURCE_VERSION:=HEAD)", "undefine PKG_SOURCE_VERSION"):
            with self.subTest(extra=extra):
                self.recipe.write_text(original+extra+"\n");self.commit();self.assertTrue(self.check())

    def test_nonliteral_assignment_operator_is_fatal(self):
        original=self.recipe.read_text()
        for operator in ("=", "?=", "+="):
            with self.subTest(operator=operator):
                self.recipe.write_text(original.replace("PKG_SOURCE_VERSION:=", "PKG_SOURCE_VERSION"+operator))
                self.commit();self.assertTrue(self.check())

    def test_missing_metadata_is_fatal(self):
        original=self.recipe.read_text()
        for name in gate.VARIABLES:
            with self.subTest(name=name):
                self.recipe.write_text("\n".join(line for line in original.splitlines() if not line.startswith(name+":="))+"\n")
                self.commit();self.assertTrue(self.check())

    def test_version_mismatch_is_fatal(self):
        self.replace("PKG_VERSION","0.8.1");self.assertTrue(self.check())

    def test_missing_invalid_or_inherited_package_version_is_fatal(self):
        original=self.cargo.read_text()
        for text in ('[package]\nname="probe"\n', '[package]\nversion.workspace=true\n',
                     'version = "0.8.2"\n[package]\nname="probe"\n', '[package]\nversion="0.8.2"\n['):
            with self.subTest(text=text):
                self.cargo.write_text(text);self.commit()
                # Pin the changed crate so version admission is the failing layer.
                self.replace("PKG_SOURCE_VERSION",self.git("rev-parse","HEAD"))
                self.assertTrue(self.check())
        self.cargo.write_text(original)

    def test_dirty_tracked_and_untracked_inputs_are_fatal(self):
        for name in ("qeli/src/lib.rs", "qeli/untracked.rs", "qeli-openwrt/Makefile", "qeli-openwrt/verify-source.sh",
                     "scripts/openwrt_source_gate.py", "scripts/release_preflight.py"):
            with self.subTest(name=name):
                path=self.root/name;path.parent.mkdir(exist_ok=True)
                old=path.read_bytes() if path.exists() else None
                path.write_bytes(b"dirty\n");self.assertTrue(self.check())
                if old is None:path.unlink()
                else:path.write_bytes(old)

    def _hidden_git_inputs_are_refused(self, flag):
        inputs=("qeli/src/lib.rs", "qeli-openwrt/Makefile", "qeli-openwrt/verify-source.sh",
                "scripts/openwrt_source_gate.py", "scripts/release_preflight.py")
        for name in inputs:
            path=self.root/name
            if not path.exists():
                path.parent.mkdir(exist_ok=True)
                path.write_text("# committed fixture\n")
                self.git("add",name)
        self.commit()
        for name in inputs:
            with self.subTest(flag=flag, input=name):
                path=self.root/name; original=path.read_bytes()
                self.git("update-index", "--"+flag, name)
                try:
                    path.write_bytes(original+b"\n// hidden input change\n")
                    self.assertEqual(self.git("status","--porcelain","--",*gate.INPUTS),"")
                    errors=self.check()
                    self.assertTrue(errors)
                    self.assertIn("Git flags",errors[0])
                finally:
                    path.write_bytes(original)
                    self.git("update-index", "--no-"+flag, name)

    def test_assume_unchanged_cannot_hide_any_source_input(self):
        self._hidden_git_inputs_are_refused("assume-unchanged")

    def test_skip_worktree_cannot_hide_any_source_input(self):
        self._hidden_git_inputs_are_refused("skip-worktree")

    def test_unrelated_git_trust_flags_do_not_broaden_input_scope(self):
        name="notes.txt";path=self.root/name;path.write_text("committed note\n")
        self.git("add",name);self.commit()
        for flag in ("assume-unchanged","skip-worktree"):
            with self.subTest(flag=flag):
                self.git("update-index","--"+flag,name)
                try:
                    path.write_text("hidden unrelated note\n")
                    self.assertEqual(self.check(),[])
                finally:
                    path.write_text("committed note\n")
                    self.git("update-index","--no-"+flag,name)

    def test_non_source_document_change_does_not_block_source_gate(self):
        (self.root/"notes.txt").write_text("unrelated review\n")
        self.assertEqual(self.check(), [])

    def test_non_tree_qeli_path_is_fatal(self):
        self.git("rm","-r","qeli")
        (self.root/"qeli").write_text("blob not a tree\n")
        self.git("add","qeli");self.git("-c","user.name=Audit Fixture","-c","user.email=audit@localhost","commit","--quiet","-m","blob")
        self.replace("PKG_SOURCE_VERSION",self.git("rev-parse","HEAD"))
        self.assertTrue(self.check())

    def test_git_timeout_missing_binary_or_failed_query_is_fatal(self):
        for value in (FileNotFoundError("git"), subprocess.TimeoutExpired("git",30),
                      subprocess.CompletedProcess([],128,"","denied")):
            with self.subTest(value=type(value).__name__):
                with patch.object(gate.subprocess,"run",side_effect=value if isinstance(value,Exception) else None,
                                  return_value=value if not isinstance(value,Exception) else None):
                    self.assertTrue(self.check())

    def test_git_queries_are_bounded_and_repository_scoped(self):
        original=gate.subprocess.run
        with patch.object(gate.subprocess,"run",side_effect=original) as run:
            self.assertEqual(self.check(), [])
        for call in run.call_args_list:
            self.assertEqual(call.kwargs["cwd"],self.root);self.assertEqual(call.kwargs["timeout"],30)

    def test_directory_archive_is_fatal(self):
        self.assertTrue(self.check(self.root))

    @unittest.skipUnless(os.name=="posix", "symlink requires POSIX fixture")
    def test_link_archive_is_fatal(self):
        link=self.root/"source-link";link.symlink_to(self.archive)
        self.assertTrue(self.check(link))

    @unittest.skipUnless(os.name=="posix", "FIFO requires POSIX")
    def test_fifo_archive_is_refused_without_reader_block(self):
        fifo=self.root/"source-fifo";os.mkfifo(fifo)
        self.assertTrue(self.check(fifo))

    def test_archive_change_during_hash_is_fatal(self):
        original=gate.hashlib.file_digest
        def change(stream,algorithm):
            result=original(stream,algorithm);self.archive.write_bytes(b"changed during hash");return result
        with patch.object(gate.hashlib,"file_digest",side_effect=change):self.assertTrue(self.check())

    def test_no_source_archive_or_git_bytes_are_mutated(self):
        before={p.relative_to(self.root):p.read_bytes() for p in self.root.rglob("*") if p.is_file()}
        self.assertEqual(self.check(), [])
        after={p.relative_to(self.root):p.read_bytes() for p in self.root.rglob("*") if p.is_file()}
        # git status may refresh index metadata; object/source/recipe/archive bytes
        # are the contract, not the index's stat cache.
        for name,data in before.items():
            if name.as_posix()!=".git/index":self.assertEqual(after[name],data,str(name))

    @unittest.skipUnless(os.environ.get("QELI_OPENWRT_SOURCE_BASELINE"), "baseline reproduction is opt-in")
    def test_exact_old_gate_accepts_regressions_new_gate_refuses(self):
        baseline=Path(os.environ["QELI_OPENWRT_SOURCE_BASELINE"]).read_text()
        section=baseline[baseline.index("# ── Gate 3:"):baseline.index("# ── Gate 4:")]
        def old():
            namespace={"ROOT":str(self.root),"os":os,"subprocess":subprocess,"failures":[]}
            with contextlib.redirect_stdout(io.StringIO()):exec(compile(section,"old-preflight","exec"),namespace)
            return namespace["failures"]
        self.assertEqual(old(), [])
        self.replace("PKG_SOURCE_VERSION","HEAD")
        self.assertEqual(old(), []);self.assertTrue(self.check())
        self.replace("PKG_SOURCE_VERSION",self.pin)
        self.recipe.write_text(self.recipe.read_text()+"PKG_SOURCE_VERSION:=HEAD\n");self.commit()
        self.assertEqual(old(), []);self.assertTrue(self.check())
        self.recipe.write_text(self.recipe.read_text().rsplit("PKG_SOURCE_VERSION:=HEAD\n",1)[0]);self.commit()
        self.archive.write_bytes(b"wrong but formatted SHA")
        self.assertEqual(old(), []);self.assertTrue(self.check())
        self.archive.write_bytes(b"mirror byte fixture\x00\r\n\x80")
        self.cargo.write_text('[package]\nname="probe"\n');self.commit()
        self.replace("PKG_SOURCE_VERSION",self.git("rev-parse","HEAD"))
        self.assertEqual(old(), []);self.assertTrue(self.check())

    def test_preflight_calls_shared_gate_and_passes_archive_path(self):
        source=(Path(__file__).parent/"release_preflight.py").read_text(encoding="utf-8")
        tree=ast.parse(source)
        calls=[n for n in ast.walk(tree) if isinstance(n,ast.Call) and isinstance(n.func,ast.Name) and n.func.id=="check_openwrt_source"]
        self.assertEqual(len(calls),1)
        argument=calls[0].args[1]
        self.assertIsInstance(argument,ast.Call)
        self.assertEqual(argument.args[0].value,"QELI_OPENWRT_SOURCE_ARCHIVE")


if __name__=="__main__":unittest.main()
