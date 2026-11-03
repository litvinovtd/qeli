"""Run the actual Windows CI publish body with failing native command fixtures."""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest


ROOT = Path(__file__).resolve().parent.parent
STEP = 'Publish both Windows distributions with required third-party notices'


def publish_body():
    lines = (ROOT / '.github/workflows/ci.yml').read_text(encoding='utf8').splitlines()
    begin = lines.index('      - name: ' + STEP)
    start = lines.index('        run: |', begin) + 1
    body = []
    for line in lines[start:]:
        if line and not line.startswith('          '):
            break
        body.append(line)
    if not body:
        raise AssertionError('Windows publication step has no executable body')
    return textwrap.dedent('\n'.join(body))


@unittest.skipUnless(os.name == 'nt', 'Windows PowerShell publication contract')
class WindowsPublishExitTests(unittest.TestCase):
    def exercise(self, fail_at):
        pwsh = shutil.which('pwsh')
        self.assertIsNotNone(pwsh, 'Windows CI requires pwsh for the publication contract')
        with tempfile.TemporaryDirectory(prefix='qeli-ci-publish-') as directory:
            root = Path(directory)
            for variant in ('net-required', 'standalone'):
                dest = root / 'dist' / variant
                (dest / 'Legal').mkdir(parents=True)
                for name in ('Wintun-LICENSE.txt', 'WinDivert-LICENSE.txt', 'WinDivert-NOTICE.txt', 'Legal/MPL-2.0.txt'):
                    (dest / name).write_text('fixture', encoding='utf8')
            # A failed publish may already have copied notices. Those files alone
            # cannot authorize its nonzero exit. Native Python processes provide
            # real exit codes; no dotnet build, restore or package is simulated.
            prefix = r'''
$ErrorActionPreference = 'stop'
$PSNativeCommandUseErrorActionPreference = $false
$script:publishCount = 0
function dotnet {
    $script:publishCount += 1
    Add-Content -LiteralPath $env:QELI_CI_CALLS -Value "publish:$script:publishCount"
    $code = if ($script:publishCount -eq [int]$env:QELI_CI_FAIL_AT) { 39 } else { 0 }
    & $env:QELI_NATIVE_PYTHON -c "import sys;sys.exit($code)"
}
function python {
    Add-Content -LiteralPath $env:QELI_CI_CALLS -Value 'legal'
    & $env:QELI_NATIVE_PYTHON -c 'import sys;sys.exit(0)'
}
'''
            # GitHub Actions' pwsh wrapper propagates only the final native exit.
            suffix = "\nif ((Test-Path -LiteralPath variable:\\LASTEXITCODE)) { exit $LASTEXITCODE }\n"
            script = root / 'run.ps1'
            script.write_text(prefix + publish_body() + suffix, encoding='utf8')
            calls = root / 'calls.txt'
            env = dict(os.environ, QELI_NATIVE_PYTHON=sys.executable,
                       QELI_CI_CALLS=str(calls), QELI_CI_FAIL_AT=str(fail_at))
            result = subprocess.run([pwsh, '-NoLogo', '-NoProfile', '-NonInteractive', '-File', str(script)],
                                    cwd=root, env=env, capture_output=True, text=True,
                                    encoding='utf8', errors='replace', timeout=30)
            observed = calls.read_text(encoding='utf-8-sig').splitlines() if calls.exists() else []
            return result.returncode, observed, result.stdout + result.stderr

    def test_first_distribution_failure_stops_before_second_publish_and_legal_checks(self):
        code, calls, output = self.exercise(1)
        self.assertNotEqual(code, 0, f'Failed first publish accepted: {calls}\n{output}')
        self.assertEqual(calls, ['publish:1'], output)

    def test_second_distribution_failure_stops_before_legal_checks(self):
        code, calls, output = self.exercise(2)
        self.assertNotEqual(code, 0, f'Failed second publish accepted: {calls}\n{output}')
        self.assertEqual(calls, ['publish:1', 'publish:2'], output)

    def test_both_successful_distributions_reach_all_legal_checks(self):
        code, calls, output = self.exercise(0)
        self.assertEqual(code, 0, output)
        self.assertEqual(calls, ['publish:1', 'publish:2'] + ['legal'] * 2, output)


if __name__ == '__main__':
    unittest.main()
