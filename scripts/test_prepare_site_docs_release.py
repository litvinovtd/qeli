"""Release preparation must not rewrite history or invent a publication."""
import copy
import json
from pathlib import Path
import tempfile
import unittest

import prepare_site_docs_release as prepare


class PrivateSiteReleaseTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.site = Path(directory.name)
        self.config = {
            "version": "0.8.3", "publishedVersion": "0.8.3",
            "changelog": [{"ver": "0.8.3", "status": "current"}],
            "perf": {"version": "0.8.0", "result": 1900},
            "compare": {"version": "0.8.3", "result": 42},
        }
        self.dictionary = {key: {"ru": "0.8.3", "en": "0.8.3"} for key in (
            "release.badge", "guide.previewLink", "installDocker.runP", "installClients.chooseP",
            "docsRecordizer.body", "release083.installBody", "changelog.sub", "docsHub.kicker")}
        self.dictionary["guide.previewP"] = {"ru": "0.8.3 выпущена как beta. Проверьте 0.8.3.", "en": "0.8.3 is released as a beta. Verify 0.8.3."}
        self.write("assets/site.json", prepare.json_text(self.config))
        self.write("assets/i18n.json", prepare.json_text(self.dictionary))
        self.write("docs/index.html", '<main>Docs 0.8.3 <a href="/blob/v0.8.3/docs/CONFIG.md">Config</a></main>')
        self.write("en/docs/index.html", '<main>Docs 0.8.3</main>')
        self.frozen = {name: '<main>Historical 0.8.3 and benchmark 0.8.0</main>' for name in (
            "changelog/index.html", "docs/reports/run/index.html", "docs/benchmarks/run/index.html", "archive/0.8.3/index.html")}
        for name, body in self.frozen.items():
            self.write(name, body)

    def write(self, name, body):
        path = self.site / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")

    def apply(self):
        changes = prepare.plan(self.site, "0.8.4")
        for path, text in changes.items():
            path.write_text(text, encoding="utf-8")
        return changes

    def test_config_history_benchmarks_and_actual_publication_are_unchanged(self):
        before = copy.deepcopy(self.config)
        self.apply()
        config = json.loads((self.site / "assets/site.json").read_text(encoding="utf-8"))
        for key in ("publishedVersion", "changelog", "perf", "compare"):
            self.assertEqual(config[key], before[key])
        self.assertEqual(config["version"], "0.8.4")
        self.assertEqual(config["documentationStatus"], "candidate")
        for name, body in self.frozen.items():
            self.assertEqual((self.site / name).read_text(encoding="utf-8"), body)

    def test_dictionary_history_is_preserved_and_released_claim_removed_in_both_languages(self):
        self.apply()
        dictionary = json.loads((self.site / "assets/i18n.json").read_text(encoding="utf-8"))
        for key in ("release083.installBody", "changelog.sub"):
            self.assertEqual(dictionary[key], self.dictionary[key])
        self.assertNotIn("выпущена", dictionary["guide.previewP"]["ru"])
        self.assertNotIn("is released", dictionary["guide.previewP"]["en"])
        for language in ("ru", "en"):
            self.assertIn("0.8.4", dictionary["docsHub.kicker"][language])
            self.assertIn("opportunistic", dictionary["docsRecordizer.body"][language])
            self.assertIn("arm64.deb", dictionary["installClients.chooseP"][language])

    def test_idempotent_and_checks_do_not_write(self):
        before = (self.site / "assets/site.json").read_bytes()
        changes = prepare.plan(self.site, "0.8.4")
        self.assertTrue(changes)
        self.assertEqual((self.site / "assets/site.json").read_bytes(), before)
        self.apply()
        self.assertEqual(prepare.plan(self.site, "0.8.4"), {})

    def test_invalid_version_and_missing_inputs_fail_closed(self):
        for version in ("latest", "0.8.4/path", "0.8"):
            with self.assertRaises(ValueError):
                prepare.plan(self.site, version)
        (self.site / "assets/i18n.json").unlink()
        with self.assertRaises(ValueError):
            prepare.plan(self.site, "0.8.4")

    def test_malformed_page_aborts_before_any_write(self):
        before = (self.site / "assets/site.json").read_bytes()
        self.write("install/index.html", "No main element")
        with self.assertRaisesRegex(ValueError, "main element"):
            prepare.plan(self.site, "0.8.4")
        self.assertEqual((self.site / "assets/site.json").read_bytes(), before)

    def test_sentence_punctuation_and_artifact_names_are_not_ip_addresses(self):
        value = "Tag v0.8.3. qeli-0.8.3.apk; 0.8.30; IP 10.8.3.7"
        self.assertEqual(prepare.replace_version(value, {"0.8.3"}, "0.8.4"),
                         "Tag v0.8.4. qeli-0.8.4.apk; 0.8.30; IP 10.8.3.7")

    def test_inline_history_and_report_links_remain_exact_inside_active_pages(self):
        history = '<section id="changelog"><div>Historical 0.8.3 release</div></section>'
        benchmark = '<div class="perf"><span>0.8.3 measured 42 Mbps</span></div>'
        report = '<a href="/docs/reports/0.8.3/result.md">Report 0.8.3</a>'
        script = '<script>const history = {version:"0.8.3"};</script>'
        self.write("index.html", '<main><p>Current 0.8.3.</p>' + history + benchmark + report + script + '</main>')
        self.apply()
        page = (self.site / "index.html").read_text(encoding="utf-8")
        self.assertIn("Current 0.8.4.", page)
        for frozen in (history, benchmark, report, script):
            self.assertIn(frozen, page)

    def test_nested_translated_history_is_protected_and_bad_history_fails_closed(self):
        text = '<p>Current 0.8.3</p><div data-i18n-html="release083.installBody"><b>Past 0.8.3</b></div>'
        self.assertEqual(prepare.rewrite_active_html(text, {"0.8.3"}, "0.8.4"), text.replace("Current 0.8.3", "Current 0.8.4"))
        with self.assertRaisesRegex(ValueError, "unclosed protected"):
            prepare.rewrite_active_html('<section id="history">0.8.3', {"0.8.3"}, "0.8.4")


if __name__ == "__main__":
    unittest.main()
