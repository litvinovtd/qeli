using System.Diagnostics;
using System.IO;
using System.Text;
namespace QeliWin.Vpn;
internal static class AdapterSharingSelfTest
{
    internal static void Run(Action<string, bool> check)
    {
        check("sharing budget is separate from five-second route timeout", AdapterSharing.TimeoutMs == 30000);
        check("driver API preserves full minor and does not invent patch/app ownership",
            AdapterSharing.DriverVersion(0x00001234).StartsWith("0.4660 ") &&
            AdapterSharing.DriverVersion(14).Contains("patch version is not reported") &&
            AdapterSharing.DriverVersion(0) == "not loaded or unavailable");
        foreach (string scenario in new[] { "owned", "slow", "missing", "duplicate", "foreign", "late_foreign", "replaced", "readback", "protocol", "protocol_missing", "binding_error" })
        {
            string mock = """
                $ErrorActionPreference='Stop'
                $script:scenario='SCENARIO'
                $script:owned=[pscustomobject]@{InterfaceGuid=[guid]'9c2c33f3-69ee-459d-89fa-981622bc6158';InterfaceDescription='Owned Wintun';Name='*[foreign]'}
                $script:foreign=[pscustomobject]@{InterfaceGuid=[guid]'9c2c33f3-69ee-459d-89fa-981622bc6159';InterfaceDescription='Foreign adapter';Name='foreign'}
                $script:changed=0
                $script:reads=0
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
                    if($script:scenario -eq 'replaced' -and $script:changed -gt 0) {return $script:foreign}
                    return @($script:foreign,$script:owned)
                }
                function Get-CimAssociatedInstance {
                    param($InputObject,$Association,$ResultClassName,$ErrorAction)
                    if($InputObject.InterfaceGuid -ne $script:owned.InterfaceGuid) {throw 'Test caught foreign adapter access'}
                    $script:reads++
                    if($script:scenario -eq 'slow' -and $script:reads -eq 1) {Start-Sleep -Milliseconds 5500}
                    if($script:scenario -eq 'foreign') {$script:sharing[0].InterfaceDescription='Foreign adapter'}
                    if($script:scenario -eq 'late_foreign') {$script:sharing[5].InterfaceDescription='Foreign adapter'}
                    return $script:sharing
                }
                function Disable-NetAdapterBinding {
                    param($InputObject,$Confirm,$ErrorAction)
                    if($InputObject.ComponentID -notin @('ms_msclient','ms_server','ms_lldp','ms_lltdio','ms_rspndr') -or $InputObject.InterfaceDescription -ne 'Owned Wintun') {throw 'Test caught foreign binding mutation'}
                    if($script:scenario -eq 'binding_error') {throw 'Access denied by fixture'}
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
                if($script:scenario -in @('owned','slow')) {
                    if($failed -or $script:changed -ne 5 -or -not $script:foreignEnabled -or -not $script:sharing[2].Enabled -or -not $script:sharing[6].Enabled -or -not $script:sharing[7].Enabled) {throw 'Owned adapter test failed'}
                    if($script:reads -ne 2) {throw 'Redundant binding enumeration'}
                    & {
                """ + AdapterSharing.BuildScript(Guid.Parse("9c2c33f3-69ee-459d-89fa-981622bc6158")) + """
                    }
                    if($script:changed -ne 5) {throw 'Reconnect repeated an already applied change'}
                } elseif(-not $failed) {throw 'Expected identity/readback failure was accepted'}
                if($script:scenario -in @('missing','duplicate','foreign','late_foreign','binding_error') -and $script:changed -ne 0) {throw 'Rejected owner still mutated a binding'}
                if($script:scenario -eq 'replaced' -and $script:changed -ne 1) {throw 'Replaced adapter was mutated again'}
                """;
            var start = new ProcessStartInfo(SystemPaths.PowerShell) {
                UseShellExecute=false, RedirectStandardOutput=true, RedirectStandardError=true,
                CreateNoWindow=true, WorkingDirectory=SystemPaths.SystemDirectory,
            };
            foreach(var argument in new[] {"-NoLogo","-NoProfile","-NonInteractive","-EncodedCommand",Convert.ToBase64String(Encoding.Unicode.GetBytes(mock))}) start.ArgumentList.Add(argument);
            try {
                var evidence = new System.Collections.Concurrent.ConcurrentQueue<string>();
                AdapterSharing.Run(start, CancellationToken.None, evidence.Enqueue);
                check("owned adapter bindings: "+scenario,
                    scenario is "owned" or "slow" || evidence.Any(line => line.Contains("QELI_ADAPTER_ERROR") && line.Contains("hresult=0x") && line.Contains("category=")));
            } catch(Exception error) {
                Console.WriteLine(error.Message);
                check("owned adapter bindings: "+scenario, false);
            }
        }
        RunnerTests(check);
    }

    private static ProcessStartInfo Fixture(string script)
    {
        var start = new ProcessStartInfo(SystemPaths.PowerShell) {
            UseShellExecute=false, RedirectStandardOutput=true, RedirectStandardError=true,
            CreateNoWindow=true, WorkingDirectory=SystemPaths.SystemDirectory,
        };
        foreach(var argument in new[] {"-NoLogo","-NoProfile","-NonInteractive","-EncodedCommand",
            Convert.ToBase64String(Encoding.Unicode.GetBytes(script))}) start.ArgumentList.Add(argument);
        return start;
    }

    private static void RunnerTests(Action<string, bool> check)
    {
        try {
            AdapterSharing.Run(new ProcessStartInfo(Path.Combine(Path.GetTempPath(), "qeli-missing-" + Guid.NewGuid().ToString("N") + ".exe")) {
                UseShellExecute=false, RedirectStandardOutput=true, RedirectStandardError=true, CreateNoWindow=true,
            }, CancellationToken.None);
            check("PowerShell start failure keeps original Win32 error", false);
        } catch(InvalidOperationException error) {
            check("PowerShell start failure keeps original Win32 error", error.Message.Contains("win32=2") && error.Message.Contains("stage=starting PowerShell"));
        }
        using(var cancelled = new CancellationTokenSource()) {
            cancelled.Cancel();
            try {
                AdapterSharing.Run(new ProcessStartInfo("must-not-start.exe"), cancelled.Token);
                check("cancel before start", false);
            } catch(OperationCanceledException) { check("cancel before start", true); }
        }
        const string waiting = "[Console]::Out.WriteLine('QELI_ADAPTER_STAGE disable-ms_server'); [Console]::Out.Flush(); [Console]::Error.WriteLine('fixture stderr before wait'); [Console]::Error.Flush(); Start-Sleep -Seconds 20";
        try {
            AdapterSharing.Run(Fixture(waiting), CancellationToken.None, timeoutMs:5000);
            check("timeout retains live stage and stderr", false);
        } catch(TimeoutException error) {
            check("timeout retains live stage and stderr", error.Message.Contains("stage=disable-ms_server") && error.Message.Contains("fixture stderr before wait") && error.Message.Contains("budget=5000ms"));
        }
        using(var cancelled = new CancellationTokenSource()) {
            try {
                AdapterSharing.Run(Fixture(waiting), cancelled.Token, message => {
                    if(message.Contains("QELI_ADAPTER_STAGE disable-ms_server")) cancelled.Cancel();
                });
                check("in-flight setup cancellation", false);
            } catch(OperationCanceledException error) {
                check("in-flight setup cancellation", error.CancellationToken == cancelled.Token && error.Message.Contains("stage=disable-ms_server"));
            }
        }
        try {
            AdapterSharing.Run(Fixture("[Console]::Out.WriteLine('QELI_ADAPTER_STAGE read-bindings'); [Console]::Error.WriteLine('fixture CIM access denied'); exit 7"), CancellationToken.None);
            check("nonzero exit preserves CIM error", false);
        } catch(InvalidOperationException error) {
            check("nonzero exit preserves CIM error", error.Message.Contains("exit 7") && error.Message.Contains("stage=read-bindings") && error.Message.Contains("fixture CIM access denied"));
        }
        try {
            AdapterSharing.Run(Fixture("1..100 | ForEach-Object { [Console]::Error.WriteLine(('x'*5000)) }; exit 9"), CancellationToken.None);
            check("bounded output diagnostics", false);
        } catch(InvalidOperationException error) {
            check("bounded output diagnostics", error.Message.Length < 35000 && error.Message.Contains("truncated"));
        }
        try {
            AdapterSharing.Run(Fixture("[Console]::Error.WriteLine('fixture original error'); 1..100 | ForEach-Object { [Console]::Out.WriteLine('stdout noise') }; exit 3"), CancellationToken.None);
            check("stdout cannot evict stderr evidence", false);
        } catch(InvalidOperationException error) {
            check("stdout cannot evict stderr evidence", error.Message.Contains("fixture original error"));
        }
    }
}
