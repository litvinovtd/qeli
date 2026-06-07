param(
    [string]$HostAddr,
    [string]$User,
    [string]$Password,
    [string]$Command
)

$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = "ssh.exe"
$psi.Arguments = "-o StrictHostKeyChecking=no -o PasswordAuthentication=yes -o ConnectTimeout=10 ${User}@${HostAddr} $Command"
$psi.UseShellExecute = $false
$psi.RedirectStandardInput = $true
$psi.RedirectStandardOutput = $true
$psi.RedirectStandardError = $true

$proc = [System.Diagnostics.Process]::Start($psi)
Start-Sleep -Seconds 2
$proc.StandardInput.WriteLine($Password)
$proc.StandardInput.Flush()
$output = $proc.StandardOutput.ReadToEnd()
$proc.WaitForExit(15000)
$output
