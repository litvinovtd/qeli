using System.Diagnostics;
using System.Text;
namespace QeliWin.Vpn;
internal static class AdapterSharingSelfTest
{
    internal static void Run(Action<string, bool> check)
    {
        foreach (string scenario in new[] { "owned", "missing", "duplicate", "foreign", "readback", "protocol", "protocol_missing" })
        {
            string mock = """
                $ErrorActionPreference='Stop'
                $script:scenario='SCENARIO'
                $script:owned=[pscustomobject]@{InterfaceGuid=[guid]'9c2c33f3-69ee-459d-89fa-981622bc6158';InterfaceDescription='Owned Wintun';Name='*[foreign]'}
                $script:foreign=[pscustomobject]@{InterfaceGuid=[guid]'9c2c33f3-69ee-459d-89fa-981622bc6159';InterfaceDescription='Foreign adapter';Name='foreign'}
                $script:changed=0
                $script:foreignEnabled=$true
                $script:sharing=@(
                    [pscustomobject]@{ComponentID='ms_msclient';Enabled=$true;InterfaceDescription='Owned Wintun'},
                    [pscustomobject]@{ComponentID='ms_server';Enabled=$true;InterfaceDescription='Owned Wintun'},
                    [pscustomobject]@{ComponentID='ms_tcpip';Enabled=$true;InterfaceDescription='Owned Wintun'},
                    [pscustomobject]@{ComponentID='ms_lldp';Enabled=$true;InterfaceDescription='Owned Wintun'},
                    [pscustomobject]@{ComponentID='ms_lltdio';Enabled=$true;InterfaceDescription='Owned Wintun'},
                    [pscustomobject]@{ComponentID='ms_rspndr';Enabled=$true;InterfaceDescription='Owned Wintun'},
                    [pscustomobject]@{ComponentID='ms_tcpip6';Enabled=$true;InterfaceDescription='Owned Wintun'},
                    [pscustomobject]@{ComponentID='third_party';Enabled=$true;InterfaceDescription='Owned Wintun'})
                function Get-NetAdapter {
                    param([switch]$IncludeHidden,$ErrorAction)
                    if($script:scenario -eq 'missing') {return $script:foreign}
                    if($script:scenario -eq 'duplicate') {return @($script:owned,$script:owned)}
                    return @($script:foreign,$script:owned)
                }
                function Get-CimAssociatedInstance {
                    param($InputObject,$Association,$ResultClassName,$ErrorAction)
                    if($InputObject.InterfaceGuid -ne $script:owned.InterfaceGuid) {throw 'Test caught foreign adapter access'}
                    if($script:scenario -eq 'foreign') {$script:sharing[0].InterfaceDescription='Foreign adapter'}
                    return $script:sharing
                }
                function Disable-NetAdapterBinding {
                    param($InputObject,$Confirm,$ErrorAction)
                    if($InputObject.ComponentID -notin @('ms_msclient','ms_server','ms_lldp','ms_lltdio','ms_rspndr') -or $InputObject.InterfaceDescription -ne 'Owned Wintun') {throw 'Test caught foreign binding mutation'}
                    $script:changed++
                    if($script:scenario -ne 'readback') {$InputObject.Enabled=$false}
                    if($script:scenario -eq 'protocol') {$script:sharing[2].Enabled=$false}
                    if($script:scenario -eq 'protocol_missing') {$script:sharing=@($script:sharing | Where-Object {$_.ComponentID -ne 'ms_tcpip'})}
                }
                foreach($name in @('Get-NetAdapter','Get-CimAssociatedInstance','Disable-NetAdapterBinding')) {
                    if((Get-Command $name).CommandType -ne 'Function') {throw 'Mock boundary is not installed'}
                }
                $failed=$false
                try { & {
                """.Replace("SCENARIO", scenario) + AdapterSharing.BuildScript(Guid.Parse("9c2c33f3-69ee-459d-89fa-981622bc6158")) + """
                }} catch {$failed=$true}
                if($script:scenario -eq 'owned') {
                    if($failed -or $script:changed -ne 5 -or -not $script:foreignEnabled -or -not $script:sharing[2].Enabled -or -not $script:sharing[6].Enabled -or -not $script:sharing[7].Enabled) {throw 'Owned adapter test failed'}
                } elseif(-not $failed) {throw 'Expected identity/readback failure was accepted'}
                if($script:scenario -in @('missing','duplicate','foreign') -and $script:changed -ne 0) {throw 'Rejected owner still mutated a binding'}
                """;
            var start = new ProcessStartInfo(SystemPaths.PowerShell) {
                UseShellExecute=false, RedirectStandardOutput=true, RedirectStandardError=true,
                CreateNoWindow=true, WorkingDirectory=SystemPaths.SystemDirectory,
            };
            foreach(var argument in new[] {"-NoLogo","-NoProfile","-NonInteractive","-EncodedCommand",Convert.ToBase64String(Encoding.Unicode.GetBytes(mock))}) start.ArgumentList.Add(argument);
            using var process=Process.Start(start) ?? throw new InvalidOperationException("Cannot start isolated PowerShell test");
            var output=process.StandardOutput.ReadToEndAsync(); var error=process.StandardError.ReadToEndAsync();
            bool finished=process.WaitForExit(5000);
            if(!finished) {try {process.Kill(true);}catch{}}
            check("owned adapter bindings: "+scenario, finished && process.ExitCode==0);
            if(finished && process.ExitCode!=0) Console.WriteLine(error.GetAwaiter().GetResult());
        }
    }
}
