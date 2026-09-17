# Requires PowerShell 7. Uses keys/agent and pre-enrolled known_hosts; never sends a password.
#Requires -Version 7.0
param(
    [Parameter(Mandatory)][ValidatePattern('^[a-zA-Z0-9_.:\[\]-]+$')][string]$HostAddr,
    [Parameter(Mandatory)][ValidatePattern('^[a-zA-Z0-9_.-]+$')][string]$User,
    [Parameter(Mandatory)][string]$Command,
    [ValidateRange(1, 3600)][int]$TimeoutSeconds = 15
)
$ErrorActionPreference = 'Stop'
$psi = [System.Diagnostics.ProcessStartInfo]::new()
$psi.FileName = 'ssh.exe'
foreach ($arg in @('-T', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
                   '-o', 'ConnectTimeout=10', '--', "${User}@${HostAddr}", $Command)) {
    $psi.ArgumentList.Add($arg)
}
$psi.UseShellExecute = $false
$psi.CreateNoWindow = $true
$psi.RedirectStandardInput = $true
$psi.RedirectStandardOutput = $true
$psi.RedirectStandardError = $true
$proc = [System.Diagnostics.Process]::Start($psi)
try {
    $proc.StandardInput.Close()
    # Both pipes drain concurrently, before waiting for the deadline.
    $stdout = $proc.StandardOutput.ReadToEndAsync()
    $stderr = $proc.StandardError.ReadToEndAsync()
    $completion = [System.Threading.Tasks.Task]::WhenAll(
        [System.Threading.Tasks.Task[]]@($stdout, $stderr, $proc.WaitForExitAsync()))
    if (!$completion.Wait($TimeoutSeconds * 1000)) {
        if (!$proc.HasExited) { $proc.Kill($true) }
        $null = $proc.WaitForExit(5000)
        throw "SSH command timed out after $TimeoutSeconds seconds (remote completion unknown)"
    }
    $output = $stdout.GetAwaiter().GetResult()
    $errorText = $stderr.GetAwaiter().GetResult()
    if ($output) { $output }
    if ($proc.ExitCode -ne 0) { throw "SSH failed ($($proc.ExitCode)): $errorText" }
    if ($errorText) { [Console]::Error.Write($errorText) }
}
finally { $proc.Dispose() }
