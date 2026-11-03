"""Release admission with real Git refs and controlled CI responses, no publication."""
import contextlib
import io
import json
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import release_tag as gate
from native_repro import DEFAULT_RUST_TOOLCHAIN
import release_certification as certification
from test_release_certification import complete_manifest


class GitFixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name); (self.root / "qeli").mkdir()
        (self.root / "qeli/Cargo.toml").write_text('[package]\nname="qeli"\nversion="0.8.2"\n', encoding="utf-8")
        self.git("init", "--quiet")
        # Fixtures must not inherit runner/user background maintenance or fsmonitor:
        # a detached writer can race TemporaryDirectory cleanup after Git returns.
        for key, value in (("gc.auto", "0"), ("maintenance.auto", "false"),
                           ("gc.autoDetach", "false"), ("maintenance.autoDetach", "false"),
                           ("core.fsmonitor", "false"),
                           ("core.hooksPath", str(self.root / ".git" / "disabled-hooks"))):
            self.git("config", "--local", key, value)
        self.git("add", ".")
        self.git("commit", "--quiet", "-m", "fixture")
        self.head = self.git("rev-parse", "HEAD")
    def git(self, *args):
        return subprocess.check_output(["git", "-c", "core.autocrlf=false", "-c", "user.name=Audit Fixture", "-c", "user.email=audit@localhost", *args], cwd=self.root, text=True).strip()
    def tag(self, annotated=False):
        self.git("tag", *(["-a", "-m", "fixture"] if annotated else []), "v0.8.2")
    def cli(self, extra=()):
        output=io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            rc=gate.main(["--repo", str(self.root), "--tag", "v0.8.2", *extra])
        return rc, output.getvalue()


class TagTests(GitFixture):
    def test_lightweight_tag_matches_exact_source_and_pin(self):
        self.tag(); self.assertEqual(gate.admit_tag(self.root,"v0.8.2"),dict(commit=self.head,version="0.8.2",rust_toolchain=DEFAULT_RUST_TOOLCHAIN))
    def test_annotated_tag_peeled_to_source_commit(self):
        self.tag(True); self.assertEqual(gate.admit_tag(self.root,"v0.8.2")["commit"],self.head)
    def test_branch_only_is_not_a_release_tag(self):
        self.git("branch","v0.8.2")
        with self.assertRaises(ValueError):gate.admit_tag(self.root,"v0.8.2")
    def test_same_name_branch_cannot_replace_other_tag_commit(self):
        self.tag();self.git("commit","--quiet","--allow-empty","-m","next");self.git("branch","v0.8.2")
        with self.assertRaisesRegex(ValueError,"checked-out"):gate.admit_tag(self.root,"v0.8.2")
    def test_missing_tag(self):
        with self.assertRaises(ValueError):gate.admit_tag(self.root,"v0.8.2")
    def test_version_mismatch(self):
        self.git("tag","v0.8.3")
        with self.assertRaisesRegex(ValueError,"Cargo version"):gate.admit_tag(self.root,"v0.8.3")
    def test_dirty_tracked_source_refused(self):
        self.tag();(self.root/"qeli/Cargo.toml").write_text('bad')
        with self.assertRaisesRegex(ValueError,"clean"):gate.admit_tag(self.root,"v0.8.2")
    def test_untracked_input_refused(self):
        self.tag();(self.root/"unexpected").write_text('input')
        with self.assertRaisesRegex(ValueError,"clean"):gate.admit_tag(self.root,"v0.8.2")
    def test_unsafe_tag_refused_before_git(self):
        for tag in ['--all','refs/heads/dev','v0.8.2\nvalue=x','v0.8.2;touch x','v0.8.2-01','v0.8.2/child']:
            with self.subTest(tag=tag),patch.object(gate,'git',side_effect=AssertionError('Git called')):
                with self.assertRaises(ValueError):gate.admit_tag(self.root,tag)
    def test_git_trust_flags_cannot_hide_modified_source(self):
        self.tag();self.git("update-index","--assume-unchanged","qeli/Cargo.toml")
        (self.root/"qeli/Cargo.toml").write_text('[package]\nversion="0.8.3"\n')
        with self.assertRaisesRegex(ValueError,"Git flags"):gate.admit_tag(self.root,"v0.8.2")
    def test_skip_worktree_source_refused(self):
        self.tag();self.git("update-index","--skip-worktree","qeli/Cargo.toml")
        with self.assertRaisesRegex(ValueError,"Git flags"):gate.admit_tag(self.root,"v0.8.2")
    def test_green_pr_cannot_publish_tag_outputs(self):
        import release_ci_gate as ci
        self.tag();out=self.root.parent/(self.root.name+'-out');self.addCleanup(lambda:out.unlink(missing_ok=True))
        out.write_bytes(b"previous output\n")
        real_query=ci._query
        def query(root,command,timeout):
            if command[0]=="gh":return json.dumps([dict(event="pull_request",headSha=self.head,status="completed",conclusion="success")])
            return real_query(root,command,timeout)
        with patch.object(ci,"_query",side_effect=query):
            rc,text=self.cli(["--require-ci","--github-output",str(out)])
        self.assertEqual(rc,1);self.assertIn("push CI",text);self.assertEqual(out.read_bytes(),b"previous output\n")

    def test_ci_failure_creates_no_output(self):
        self.tag();out=self.root.parent/(self.root.name+'-out');self.addCleanup(lambda:out.unlink(missing_ok=True))
        with patch.object(gate,'check_release_ci',return_value=['CI failed']):
            rc,text=self.cli(['--require-ci','--github-output',str(out)])
        self.assertEqual(rc,1);self.assertIn('CI failed',text);self.assertFalse(out.exists())
    def test_exact_commit_ci_selector_and_outputs(self):
        self.tag();out=self.root.parent/(self.root.name+'-out');self.addCleanup(lambda:out.unlink(missing_ok=True))
        with patch.object(gate,'check_release_ci',return_value=[]) as ci:
            rc,text=self.cli(['--require-ci','--github-output',str(out)])
        self.assertEqual(rc,0);ci.assert_called_once_with(self.root,'v0.8.2',by_commit=True)
        self.assertEqual(out.read_bytes(),f'commit={self.head}\nversion=0.8.2\nrust_toolchain={DEFAULT_RUST_TOOLCHAIN}\n'.encode())
    def test_source_change_during_ci_admission_refused(self):
        self.tag()
        def change(*args,**kwargs):self.git('commit','--quiet','--allow-empty','-m','changed');return []
        with patch.object(gate,'check_release_ci',side_effect=change):rc,text=self.cli(['--require-ci'])
        self.assertEqual(rc,1);self.assertIn('checked-out',text)
    def test_missing_git_or_timeout_returns_refusal(self):
        for error in [FileNotFoundError('git'),subprocess.TimeoutExpired('git',30)]:
            with patch.object(gate.subprocess,'run',side_effect=error):rc,text=self.cli()
            self.assertEqual(rc,1)


class CIWaitTests(GitFixture):
    def setUp(self):
        super().setUp()
        self.tag()
        self.elapsed = 0
        self.delays = []
        self.timer = SimpleNamespace(monotonic=lambda: self.elapsed, sleep=self.sleep)
        self.output = self.root.parent / (self.root.name + '-outputs')
        self.addCleanup(lambda: self.output.unlink(missing_ok=True))
        self.output.write_bytes(b'existing=kept\n')

    def sleep(self, seconds):
        self.delays.append(seconds)
        self.elapsed += seconds

    def wait_cli(self, seconds='90'):
        return self.cli(['--require-ci', '--wait-ci', seconds,
                         '--github-output', str(self.output)])

    def test_real_ci_reader_waits_for_same_commit_push_before_outputs(self):
        import release_ci_gate as ci
        real_query = ci._query
        statuses = iter(['queued', 'in_progress', 'completed'])
        queries = []

        def query(root, command, timeout):
            if command[0] == 'gh':
                queries.append(command)
                status = next(statuses)
                return json.dumps([dict(event='push', headSha=self.head, status=status,
                    conclusion='success' if status == 'completed' else '', databaseId=123)])
            return real_query(root, command, timeout)

        with patch.object(gate, 'time', self.timer), patch.object(ci, '_query', side_effect=query):
            rc, text = self.wait_cli()
        self.assertEqual(rc, 0, text)
        self.assertEqual(self.delays, [30, 30])
        self.assertEqual(len(queries), 3)
        for command in queries:
            self.assertEqual(command[command.index('--commit') + 1], self.head)
        self.assertEqual(self.output.read_text(), 'existing=kept\n' +
            f'commit={self.head}\nversion=0.8.2\nrust_toolchain={DEFAULT_RUST_TOOLCHAIN}\n')

    def test_timeout_is_bounded_and_preserves_output(self):
        with patch.object(gate, 'time', self.timer), patch.object(gate, 'check_release_ci',
                return_value=['CI still running (in_progress)']) as query:
            rc, text = self.wait_cli('5')
        self.assertEqual(rc, 1, text)
        self.assertIn('Timed out', text)
        self.assertEqual(self.delays, [5])
        self.assertEqual(query.call_count, 1)
        self.assertEqual(self.output.read_bytes(), b'existing=kept\n')

    def test_failed_missing_unknown_and_mismatched_ci_never_wait(self):
        failures = [
            ['CI conclusion=failure'], ['CI conclusion=cancelled'],
            ['CI admission failed: no push CI run found'],
            ['CI still running (unexpected_status)'],
            ['CI ran on another commit', 'CI still running (queued)'],
            ['CI admission failed: release coverage requires a push CI run'],
        ]
        for errors in failures:
            with self.subTest(errors=errors), patch.object(gate, 'time', self.timer), \
                    patch.object(gate, 'check_release_ci', return_value=errors) as query:
                rc, text = self.wait_cli()
            self.assertEqual(rc, 1, text)
            self.assertEqual(query.call_count, 1)
            self.assertEqual(self.delays, [])
            self.assertEqual(self.output.read_bytes(), b'existing=kept\n')

    def test_changed_source_during_wait_refuses_before_requery(self):
        def change(seconds):
            self.sleep(seconds)
            (self.root / 'qeli/Cargo.toml').write_text('changed')
        self.timer.sleep = change
        with patch.object(gate, 'time', self.timer), patch.object(gate, 'check_release_ci',
                return_value=['CI still running (queued)']) as query:
            rc, text = self.wait_cli()
        self.assertEqual(rc, 1, text)
        self.assertIn('clean', text)
        self.assertEqual(query.call_count, 1)
        self.assertEqual(self.output.read_bytes(), b'existing=kept\n')

    def test_default_remains_immediate_refusal_for_pending_ci(self):
        with patch.object(gate, 'time', self.timer), patch.object(gate, 'check_release_ci',
                return_value=['CI still running (queued)']) as query:
            rc, text = self.cli(['--require-ci', '--github-output', str(self.output)])
        self.assertEqual(rc, 1, text)
        self.assertEqual(query.call_count, 1)
        self.assertEqual(self.delays, [])
        self.assertEqual(self.output.read_bytes(), b'existing=kept\n')

    def test_invalid_wait_refuses_before_git(self):
        for args in (['--wait-ci', '-1', '--require-ci'], ['--wait-ci', '3601', '--require-ci'],
                     ['--wait-ci', '10']):
            with self.subTest(args=args), patch.object(gate, 'admit_tag',
                    side_effect=AssertionError('Git queried')):
                with self.assertRaises(SystemExit) as error:
                    self.cli(args)
                self.assertEqual(error.exception.code, 2)


class PublisherCertificationTests(GitFixture):
    def setUp(self):
        super().setUp()
        self.manifest = self.root / "release/certification/0.8.2.json"
        self.manifest.parent.mkdir(parents=True)
        self.document = complete_manifest()
        self.document["release_version"] = "0.8.2"
        digest = certification.repository_source_digest(self.root)
        self.document["source_digest"] = digest
        for case in self.document["cases"]:
            if "source_digest" in case:case["source_digest"] = digest
        self.record()

    def record(self):
        self.manifest.write_text(json.dumps(self.document) + "\n", encoding="utf8")
        self.git("add", "--", "release/certification")
        self.git("commit", "--quiet", "--allow-empty", "-m", "certification")
        self.head = self.git("rev-parse", "HEAD")
        self.git("tag", "-f", "v0.8.2")

    def publication(self, ci=None):
        # GITHUB_OUTPUT lives outside the source fixture, as on Actions.
        output = Path(self.temp.name).parent / (Path(self.temp.name).name + "-outputs")
        self.addCleanup(lambda: output.unlink(missing_ok=True))
        output.write_text("existing=kept\n")
        with patch.object(gate, "check_release_ci", return_value=[] if ci is None else ci) as query:
            rc, text = self.cli(["--require-ci", "--require-certification",
                                 "--github-output", str(output)])
        return rc, text, output.read_text(), query

    def test_failed_automated_case_refuses_before_ci_and_outputs(self):
        self.document["cases"][0]["status"] = "failed"; self.record()
        rc, text, output, query = self.publication()
        self.assertEqual(rc, 1, text); self.assertIn("status is 'failed'", text)
        self.assertEqual(output, "existing=kept\n"); query.assert_not_called()

    def test_missing_stale_and_malformed_manifests_refuse(self):
        for mode in ("missing", "stale", "malformed"):
            with self.subTest(mode=mode):
                if mode == "missing":self.manifest.unlink()
                elif mode == "stale":
                    data=dict(self.document, source_digest="e"*64)
                    self.manifest.write_text(json.dumps(data),encoding="utf8")
                else:self.manifest.write_text("{",encoding="utf8")
                self.git("add", "--", "release/certification")
                self.git("commit", "--quiet", "-m", mode)
                self.git("tag", "-f", "v0.8.2")
                rc, text, output, query = self.publication()
                self.assertEqual(rc, 1, text); self.assertEqual(output, "existing=kept\n")
                query.assert_not_called()
                self.record()

    def test_physical_failure_blocks_but_unavailable_remains_advisory(self):
        case = self.document["cases"][len(certification.REQUIRED_CASES)]
        for status, expected in (("failed", 1), ("not_available", 0)):
            with self.subTest(status=status):
                case["status"] = status; self.record()
                rc, text, output, query = self.publication()
                self.assertEqual(rc, expected, text)
                if expected:
                    self.assertEqual(output, "existing=kept\n"); query.assert_not_called()
                else:query.assert_called_once()

    def test_valid_evidence_and_ci_write_metadata_only_after_admission(self):
        rc, text, output, query = self.publication()
        self.assertEqual(rc, 0, text)
        self.assertEqual(output, f"existing=kept\ncommit={self.head}\nversion=0.8.2\nrust_toolchain={DEFAULT_RUST_TOOLCHAIN}\n")
        query.assert_called_once_with(self.root, "v0.8.2", by_commit=True)
        rc, text, output, _ = self.publication(["CI refused"])
        self.assertEqual(rc, 1, text); self.assertEqual(output, "existing=kept\n")

    def test_manifest_or_head_change_during_validation_refuses(self):
        original = gate.load_and_validate
        for mode in ("manifest", "head"):
            with self.subTest(mode=mode):
                if mode == "head":
                    self.git("commit", "--quiet", "--allow-empty", "-m", "next")
                    other = self.git("rev-parse", "HEAD")
                    self.git("checkout", "--quiet", "--detach", self.head)
                def validate(*args):
                    result = original(*args)
                    if mode == "manifest":self.manifest.write_text("{}")
                    else:self.git("checkout", "--quiet", other)
                    return result
                with patch.object(gate,"load_and_validate",side_effect=validate):
                    rc,text,output,query=self.publication()
                self.assertEqual(rc,1,text);self.assertEqual(output,"existing=kept\n")
                query.assert_not_called()
                if mode == "manifest":self.git("checkout", "--", "release/certification")
                else:self.git("checkout","--quiet","--detach",self.head)

    def test_validator_io_and_identity_failure_are_refusals(self):
        for error in (OSError("manifest unreadable"), certification.CertificationError("identity refused")):
            with self.subTest(error=type(error).__name__):
                with patch.object(gate,"load_and_validate",side_effect=error):
                    rc,text,output,query=self.publication()
                self.assertEqual(rc,1,text);self.assertEqual(output,"existing=kept\n")
                query.assert_not_called()

    def test_actual_cli_certification_success_and_failed_case_refusal(self):
        output=Path(self.temp.name).parent/(Path(self.temp.name).name+"-cli-output")
        self.addCleanup(lambda:output.unlink(missing_ok=True))
        command=[__import__("sys").executable,"-B",gate.__file__,"--repo",str(self.root),
                 "--tag","v0.8.2","--require-certification","--github-output",str(output)]
        accepted=subprocess.run(command,capture_output=True,text=True,timeout=30)
        self.assertEqual(accepted.returncode,0,accepted.stderr)
        self.assertEqual(json.loads(accepted.stdout)["status"],"PASS")
        self.document["cases"][0]["status"]="failed";self.record()
        output.write_text("existing=kept\n")
        refused=subprocess.run(command,capture_output=True,text=True,timeout=30)
        self.assertEqual(refused.returncode,1,refused.stderr)
        self.assertNotIn('"status": "PASS"',refused.stdout)
        self.assertEqual(output.read_text(),"existing=kept\n")

    def test_tag_admission_precedes_certification_and_ci(self):
        self.git("tag","-d","v0.8.2")
        with patch.object(gate,"load_and_validate") as validate:
            rc,text,output,query=self.publication()
        self.assertEqual(rc,1,text);self.assertEqual(output,"existing=kept\n")
        validate.assert_not_called();query.assert_not_called()


class WorkflowTests(unittest.TestCase):
    def test_release_and_docker_bind_pin_and_legal_gates(self):
        root=Path(__file__).resolve().parent.parent
        s=(root/'.github/workflows/release-attest.yml').read_text(encoding='utf-8')
        self.assertIn('ref: refs/tags/${{',s);self.assertIn('actions: read',s)
        self.assertLess(s.index('--require-ci'),s.index('Install the portable'))
        self.assertIn('toolchain: ${{ steps.meta.outputs.rust_toolchain }}',s)
        self.assertIn('--bundle "$extracted/usr/share/doc/qeli/licenses/rust"',s)
        s=(root/'.github/workflows/docker-publish.yml').read_text(encoding='utf-8')
        self.assertLess(s.index('python3 scripts/native_licenses.py'),s.index('docker/login-action@'))
        s=(root/'release/docker/Dockerfile').read_text(encoding='utf-8')
        self.assertRegex(s,r'FROM rust:'+DEFAULT_RUST_TOOLCHAIN.replace('.',r'\.')+r'-bookworm@sha256:[0-9a-f]{64} AS build')
        self.assertRegex(s,r'FROM debian:bookworm-slim@sha256:[0-9a-f]{64}')
        self.assertIn('COPY LICENSE LICENSING.md /usr/share/doc/qeli/',s)
        self.assertIn('COPY qeli/third-party-notices/rust /usr/share/doc/qeli/licenses/rust',s)
    def test_docker_frontend_is_digest_pinned(self):
        recipe=(Path(__file__).resolve().parent.parent/'release/docker/Dockerfile').read_text(encoding='utf-8')
        self.assertRegex(recipe.splitlines()[0],r'^# syntax=docker/dockerfile:1@sha256:[0-9a-f]{64}$')

    def test_docker_apt_uses_only_one_signed_snapshot_cut(self):
        root=Path(__file__).resolve().parent.parent
        recipe=(root/'release/docker/Dockerfile').read_text(encoding='utf-8')
        policy=(root/'release/docker/debian.sources').read_text(encoding='utf-8')
        sections=[dict(line.split(': ',1) for line in block.splitlines() if line and not line.startswith('#')) for block in policy.strip().split('\n\n')]
        self.assertEqual(len(sections),2)
        import re
        cuts=[]
        for section in sections:
            self.assertEqual(section['Types'],'deb')
            self.assertEqual(section['Components'],'main')
            self.assertEqual(section['Signed-By'],'/usr/share/keyrings/debian-archive-keyring.gpg')
            self.assertEqual(section['Check-Valid-Until'],'no')
            self.assertNotIn('Trusted',section)
            cut=re.fullmatch(r'http://snapshot\.debian\.org/archive/(debian|debian-security)/(\d{8}T\d{6}Z)',section['URIs'])
            self.assertIsNotNone(cut);cuts.append(cut.group(2))
        self.assertEqual(cuts[0],cuts[1])
        self.assertEqual(sections[0]['Suites'],'bookworm bookworm-updates')
        self.assertEqual(sections[1]['Suites'],'bookworm-security')
        clear='RUN rm -f /etc/apt/sources.list /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources'
        copy='COPY release/docker/debian.sources /etc/apt/sources.list.d/qeli-snapshot.sources'
        self.assertLess(recipe.index(clear),recipe.index(copy))
        self.assertLess(recipe.index(copy),recipe.index('RUN apt-get update'))
        self.assertNotIn('--allow-unauthenticated',recipe)
        self.assertNotIn('AllowInsecureRepositories',recipe)

    def test_build_attestation_covers_only_the_locally_built_package(self):
        source=(Path(__file__).resolve().parent.parent/'.github/workflows/release-attest.yml').read_text(encoding='utf-8')
        actions=[line.strip() for line in source.splitlines() if 'uses: actions/attest' in line]
        self.assertEqual(actions,['uses: actions/attest-build-provenance@96278af6caaf10aea03fd8d33a09a777ca52d62f # v3.2.0'])
        attest=source.split('      - name: Attest the CI-built Linux package',1)[1].split('      - name:',1)[0]
        self.assertIn('subject-path: ${{ steps.assets.outputs.subject }}',attest)
        self.assertNotIn('dist/*',attest)
        self.assertIn('echo "subject=dist/${{ steps.pkg.outputs.name }}"',source)

    def test_docker_release_uses_exact_tag_version_ci_admission_before_login(self):
        source=(Path(__file__).resolve().parent.parent/'.github/workflows/docker-publish.yml').read_text(encoding='utf-8')
        self.assertIn('actions: read',source)
        self.assertIn('ref: ${{ github.ref }}',source)
        self.assertIn('fetch-depth: 0',source)
        self.assertIn("if: steps.ref.outputs.release_tag == 'true'",source)
        command='python3 scripts/release_tag.py --tag "$GITHUB_REF_NAME" --require-ci'
        self.assertLess(source.index('python3 -B scripts/docker_publish_ref.py'),source.index(command))
        self.assertLess(source.index(command),source.index('docker/login-action@'))
        self.assertIn('GH_TOKEN: ${{ github.token }}',source)

    def test_ci_covers_every_workflow_change(self):
        s=(Path(__file__).resolve().parent.parent/'.github/workflows/ci.yml').read_text(encoding='utf-8')
        events=s.split("\non:\n",1)[1].split("\nenv:\n",1)[0]
        self.assertIn("  push:\n",events);self.assertIn("  pull_request:\n",events)
        self.assertNotIn("paths:",events);self.assertNotIn("paths-ignore:",events)
        self.assertIn("'test_release_tag.py'",s)


    def test_publishers_require_runtime_certification_before_build_and_login(self):
        root=Path(__file__).resolve().parent.parent
        release=(root/".github/workflows/release-attest.yml").read_text(encoding="utf8")
        docker=(root/".github/workflows/docker-publish.yml").read_text(encoding="utf8")
        for source,boundary in ((release,"make -C qeli/debian"),(docker,"docker/login-action@")):
            start=source.index("python3 scripts/release_tag.py")
            command=source[start:].splitlines()[0]
            self.assertIn("--require-ci",command)
            self.assertIn("--wait-ci 1800",command)
            self.assertIn("--require-certification",command)
            self.assertLess(start,source.index(boundary))


if __name__=='__main__':unittest.main()
