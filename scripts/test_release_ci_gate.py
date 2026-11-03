"""Exact-commit release CI admission with real Git and controlled gh responses."""
import ast
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import release_ci_gate as gate

HEAD = "a" * 40
OTHER = "b" * 40


class AdmissionTests(unittest.TestCase):
    def check(self, run=None, git=None, gh=None, branch="dev"):
        if run is None:
            run = {"event": "push", "headSha": HEAD, "status": "completed", "conclusion": "success"}
        outputs = [git if git is not None else subprocess.CompletedProcess([], 0, HEAD, ""),
                   gh if gh is not None else subprocess.CompletedProcess([], 0, json.dumps([run]), "")]
        with patch.object(gate.subprocess, "run", side_effect=outputs) as query:
            errors = gate.check_release_ci(Path("fixture-root"), branch, lambda _: None)
        return errors, query

    def test_exact_commit_selector_does_not_need_a_branch(self):
        outputs = [subprocess.CompletedProcess([],0,HEAD,"") ,
                   subprocess.CompletedProcess([],0,json.dumps([{"event": "push", "headSha":HEAD,"status":"completed","conclusion":"success"}]),"")]
        with patch.object(gate.subprocess,"run",side_effect=outputs) as query:
            self.assertEqual(gate.check_release_ci(Path("fixture-root"),None,lambda _:None,by_commit=True),[])
        command=query.call_args_list[1].args[0]
        self.assertIn("--commit",command);self.assertEqual(command[command.index("--commit")+1],HEAD);self.assertNotIn("--branch",command)
        self.assertEqual(command[command.index("--event")+1],"push");self.assertIn("event",command[command.index("--json")+1].split(","))

    def test_exact_green_commit_passes(self):
        errors, query = self.check()
        self.assertEqual(errors, [])
        for call in query.call_args_list:
            self.assertEqual(call.kwargs["cwd"], Path("fixture-root"))
            self.assertGreater(call.kwargs["timeout"], 0)
        self.assertEqual(query.call_args_list[0].args[0], ["git", "rev-parse", "HEAD^{commit}"])
        command=query.call_args_list[1].args[0];self.assertEqual(command[command.index("--event")+1],"push")

    def test_green_pull_request_with_exact_head_refuses_release(self):
        errors, _ = self.check(run={"event":"pull_request","headSha":HEAD,"status":"completed","conclusion":"success"})
        self.assertEqual(len(errors),1);self.assertIn("push CI",errors[0])

    def test_missing_unknown_manual_and_scheduled_events_refuse_release(self):
        for event in (None,"",42,"pull_request_target","workflow_dispatch","schedule"):
            with self.subTest(event=event):
                errors, _ = self.check(run={"event":event,"headSha":HEAD,"status":"completed","conclusion":"success"})
                self.assertEqual(len(errors),1);self.assertIn("push CI",errors[0])
        errors, _ = self.check(run={"headSha":HEAD,"status":"completed","conclusion":"success"})
        self.assertEqual(len(errors),1)

    def test_git_error_cannot_accept_green_ci_or_query_github(self):
        errors, query = self.check(git=subprocess.CompletedProcess([], 128, "", "git denied"))
        self.assertEqual(len(errors), 1)
        self.assertIn("git denied", errors[0])
        self.assertEqual(query.call_count, 1)

    def test_empty_or_invalid_local_commit_is_fatal(self):
        for head in ("", "short", HEAD + "\n" + OTHER):
            with self.subTest(head=head):
                errors, query = self.check(git=subprocess.CompletedProcess([], 0, head, ""))
                self.assertEqual(len(errors), 1)
                self.assertEqual(query.call_count, 1)

    def test_empty_missing_invalid_ci_commit_is_fatal(self):
        for head in (None, "", "short", 42):
            with self.subTest(head=head):
                errors, _ = self.check(run={"event": "push", "headSha": head, "status": "completed", "conclusion": "success"})
                self.assertEqual(len(errors), 1)
                self.assertIn("headSha", errors[0])
        errors, _ = self.check(run={"status": "completed", "conclusion": "success"})
        self.assertEqual(len(errors), 1)

    def test_old_green_commit_is_fatal(self):
        errors, _ = self.check(run={"event": "push", "headSha": OTHER, "status": "completed", "conclusion": "success"})
        self.assertEqual(len(errors), 1)
        self.assertIn("not on the commit", errors[0])

    def test_pending_or_failed_run_is_fatal(self):
        for status, conclusion in (("queued", None), ("in_progress", None),
                                   ("completed", "failure"), ("completed", "cancelled"),
                                   ("completed", None), ("completed", "skipped")):
            with self.subTest(status=status, conclusion=conclusion):
                errors, _ = self.check(run={"event": "push", "headSha": HEAD, "status": status, "conclusion": conclusion})
                self.assertEqual(len(errors), 1)

    def test_unknown_ci_status_is_fatal(self):
        for status in (None, "", 42, "unknown"):
            with self.subTest(status=status):
                errors, _ = self.check(run={"event": "push", "headSha": HEAD, "status": status, "conclusion": "success"})
                self.assertEqual(len(errors), 1)

    def test_no_run_malformed_json_or_response_is_fatal(self):
        for payload in ("[]", "null", "{}", "[null]", "[42]", "[", "false"):
            with self.subTest(payload=payload):
                errors, _ = self.check(gh=subprocess.CompletedProcess([], 0, payload, ""))
                self.assertEqual(len(errors), 1)

    def test_github_query_failure_is_fatal(self):
        errors, _ = self.check(gh=subprocess.CompletedProcess([], 1, "", "gh denied"))
        self.assertEqual(len(errors), 1)
        self.assertIn("gh denied", errors[0])

    def test_missing_tools_or_command_timeout_is_fatal(self):
        for error in (FileNotFoundError("missing git"), FileNotFoundError("missing gh"),
                      subprocess.TimeoutExpired("gh", 120)):
            with self.subTest(error=type(error).__name__), patch.object(gate.subprocess, "run", side_effect=error):
                errors = gate.check_release_ci(Path("fixture"), "dev", lambda _: None)
                self.assertEqual(len(errors), 1)

    def test_missing_or_detached_branch_is_fatal_before_commands(self):
        for branch in (None, "", " ", "HEAD"):
            with self.subTest(branch=branch):
                errors, query = self.check(branch=branch)
                self.assertEqual(len(errors), 1)
                query.assert_not_called()

    def test_stale_and_failed_run_report_both_reasons(self):
        errors, _ = self.check(run={"event": "push", "headSha": OTHER, "status": "completed", "conclusion": "failure"})
        self.assertEqual(len(errors), 2)

    def test_sha256_git_identity_can_be_compared(self):
        sha = "c" * 64
        errors, _ = self.check(git=subprocess.CompletedProcess([], 0, sha, ""),
                              run={"event": "push", "headSha": sha, "status": "completed", "conclusion": "success"})
        self.assertEqual(errors, [])

    def test_failed_job_details_are_retained_as_diagnostics(self):
        response = {"event": "push", "headSha": HEAD, "status": "completed", "conclusion": "failure", "databaseId": 7}
        outputs = [subprocess.CompletedProcess([], 0, HEAD, ""),
                   subprocess.CompletedProcess([], 0, json.dumps([response]), ""),
                   subprocess.CompletedProcess([], 0, json.dumps({"jobs": [
                       {"name": "native-libs", "conclusion": "failure"},
                       {"name": "docs", "conclusion": "success"}]}), "")]
        messages = []
        with patch.object(gate.subprocess, "run", side_effect=outputs) as query:
            errors = gate.check_release_ci(Path("fixture-root"), "dev", messages.append)
        self.assertEqual(len(errors), 1)
        self.assertIn("    FAILED: native-libs = failure", messages)
        self.assertEqual(query.call_args.args[0], ["gh", "run", "view", "7", "--json", "jobs"])
        self.assertEqual(query.call_args.kwargs["cwd"], Path("fixture-root"))

    def test_job_diagnostic_error_cannot_hide_failure_or_abort_gate(self):
        response = {"event": "push", "headSha": HEAD, "status": "completed", "conclusion": "failure", "databaseId": 7}
        for detail in (FileNotFoundError("missing gh"), subprocess.CompletedProcess([], 0, "{", ""),
                       subprocess.CompletedProcess([], 1, "", "gh denied")):
            with self.subTest(detail=type(detail).__name__):
                outputs = [subprocess.CompletedProcess([], 0, HEAD, ""),
                           subprocess.CompletedProcess([], 0, json.dumps([response]), ""), detail]
                messages = []
                with patch.object(gate.subprocess, "run", side_effect=outputs):
                    errors = gate.check_release_ci(Path("fixture"), "dev", messages.append)
                self.assertEqual(len(errors), 1)
                self.assertTrue(any("failed-job details unavailable" in m for m in messages))

    def test_real_git_identity_uses_release_root_from_another_directory(self):
        with tempfile.TemporaryDirectory(prefix="qeli-ci-git-") as directory:
            root = Path(directory)
            subprocess.run(["git", "init", "--quiet"], cwd=root, check=True)
            subprocess.run(["git", "-c", "user.name=Audit Fixture", "-c", "user.email=audit@localhost",
                            "commit", "--quiet", "--allow-empty", "-m", "fixture"], cwd=root, check=True)
            head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
            real_run = subprocess.run
            calls = []
            def query(command, **kwargs):
                calls.append((command, kwargs))
                if command[0] == "gh":
                    return subprocess.CompletedProcess(command, 0, json.dumps([{
                        "event": "push", "headSha": head, "status": "completed", "conclusion": "success"}]), "")
                return real_run(command, **kwargs)
            with patch.object(gate.subprocess, "run", side_effect=query):
                self.assertEqual(gate.check_release_ci(root, "dev", lambda _: None), [])
            self.assertEqual(calls[0][1]["cwd"], root)
            self.assertEqual(calls[1][1]["cwd"], root)


class CallerTests(unittest.TestCase):
    def test_preflight_accumulates_gate_failure_and_can_continue(self):
        path = Path(__file__).with_name("release_preflight.py")
        tree = ast.parse(path.read_text(encoding="utf-8"))
        nodes = [n for n in ast.walk(tree) if isinstance(n, ast.Expr) and isinstance(n.value, ast.Call)
                 and isinstance(n.value.func, ast.Attribute) and n.value.func.attr == "extend"
                 and any(isinstance(v, ast.Call) and isinstance(v.func, ast.Name)
                         and v.func.id == "check_release_ci" for v in n.value.args)]
        self.assertEqual(len(nodes), 1)
        state = {"ROOT": "fixture-root", "BRANCH": "dev", "failures": ["prior gate"],
                 "check_release_ci": lambda root, branch: ["CI rejected"]}
        exec(compile(ast.Module(body=nodes, type_ignores=[]), str(path), "exec"), state)
        self.assertEqual(state["failures"], ["prior gate", "CI rejected"])

    def test_default_branch_lookup_uses_repository_root(self):
        tree = ast.parse(Path(__file__).with_name("release_preflight.py").read_text(encoding="utf-8"))
        node = next(n for n in ast.walk(tree) if isinstance(n, ast.Assign)
                    and any(isinstance(v, ast.Name) and v.id == "BRANCH" for v in n.targets))
        call = next(n for n in ast.walk(node) if isinstance(n, ast.Call)
                    and isinstance(n.func, ast.Attribute) and n.func.attr == "run")
        self.assertTrue(any(k.arg == "cwd" and isinstance(k.value, ast.Name)
                            and k.value.id == "ROOT" for k in call.keywords))


if __name__ == "__main__":
    unittest.main()
