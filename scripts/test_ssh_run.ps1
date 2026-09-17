#Requires -Version 7.0
# Run the production process/deadline block against local child processes, never SSH.
$ErrorActionPreference = 'Stop'
$source = Get-Content -Raw (Join-Path $PSScriptRoot 'ssh-run.ps1')
$offset = $source.IndexOf('$proc = [System.Diagnostics.Process]::Start($psi)')
if ($offset -lt 0) { throw 'production process block not found' }
$body = [scriptblock]::Create($source.Substring($offset))
function Invoke-TestChild([string]$code, [int]$seconds) {
    $psi = [System.Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = (Get-Process -Id $PID).Path
    foreach ($arg in @('-NoProfile', '-NonInteractive', '-Command', $code)) { $psi.ArgumentList.Add($arg) }
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardInput = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $TimeoutSeconds = $seconds
    & $body
}
# Failure includes the captured stderr, so both full pipes must have drained.
try {
    $null = Invoke-TestChild "[Console]::Out.Write('a' * 100000); [Console]::Error.Write('b' * 100000); exit 7" 10
    throw 'nonzero child unexpectedly succeeded'
} catch {
    if (!$_.Exception.Message.StartsWith('SSH failed (7):') -or $_.Exception.Message.Length -lt 100000) { throw }
}
$watch = [Diagnostics.Stopwatch]::StartNew()
try {
    $null = Invoke-TestChild 'Start-Sleep -Seconds 30' 1
    throw 'hanging child unexpectedly succeeded'
} catch {
    if (!$_.Exception.Message.Contains('timed out')) { throw }
}
if ($watch.Elapsed.TotalSeconds -gt 8) { throw 'deadline did not bound process lifetime' }
if (!(Invoke-TestChild "[Console]::Out.Write('OK')" 10).Contains('OK')) { throw 'stdout lost' }
if (!$source.Contains('StrictHostKeyChecking=yes') -or !$source.Contains('BatchMode=yes')) {
    throw 'SSH must use enrolled host keys and noninteractive authentication'
}
'PASS: parallel pipes, nonzero exit, deadline, stdout and strict SSH options'
