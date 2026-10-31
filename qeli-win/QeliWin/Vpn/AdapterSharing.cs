using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
namespace QeliWin.Vpn;

internal static class AdapterSharing
{
    [DllImport("iphlpapi.dll")]
    private static extern uint ConvertInterfaceLuidToGuid(in ulong luid, out Guid guid);

    internal static void Apply(WintunAdapter adapter, Func<ProcessStartInfo, string, string> run)
    {
        // Hold the creator handle through identity checks + the bounded command. The
        // adapter cannot be disposed/replaced by this process while bindings are changed.
        adapter.WithOwnedIdentity((luid, createdGuid) =>
        {
            uint result = ConvertInterfaceLuidToGuid(in luid, out var actualGuid);
            if (result != 0) throw new Win32Exception((int)result, "Cannot resolve owned Wintun GUID");
            if (actualGuid != createdGuid) throw new InvalidOperationException("Owned Wintun LUID/GUID mismatch");
            var start = new ProcessStartInfo(SystemPaths.PowerShell) {
                UseShellExecute = false, RedirectStandardOutput = true,
                RedirectStandardError = true, CreateNoWindow = true,
                WorkingDirectory = SystemPaths.SystemDirectory,
            };
            foreach (var argument in new[] { "-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand",
                Convert.ToBase64String(Encoding.Unicode.GetBytes(BuildScript(actualGuid))) }) start.ArgumentList.Add(argument);
            _ = run(start, "disable sharing bindings on owned Qeli adapter");
        });
    }

    // Microsoft NetAdapterBindingElementSetting links the exact CIM adapter to
    // its binding instances. No alias interpolation, wildcard lookup or blanket disable.
    // https://learn.microsoft.com/en-us/windows/win32/fwp/wmi/netadaptercimprov/msft-netadapterbindingelementsetting
    internal static string BuildScript(Guid guid)
    {
        if (guid == Guid.Empty) throw new ArgumentException("Adapter GUID is empty", nameof(guid));
        return "$ErrorActionPreference='Stop'; $expected=[guid]'" + guid.ToString("D") + "';" + """
            function OwnedAdapter {
                $ownedAdapters=@(Get-NetAdapter -IncludeHidden -ErrorAction Stop | Where-Object { [guid]$_.InterfaceGuid -eq $expected })
                if ($ownedAdapters.Count -ne 1) { throw 'Owned Qeli adapter identity is missing or ambiguous' }
                return $ownedAdapters[0]
            }
            function Bindings {
                param($adapter)
                return @(Get-CimAssociatedInstance -InputObject $adapter -Association MSFT_NetAdapterBindingElementSetting -ResultClassName MSFT_NetAdapterBindingSettingData -ErrorAction Stop)
            }
            $adapter=OwnedAdapter
            $all=Bindings $adapter
            $protocols=@{}
            foreach ($binding in $all) {
                if ($binding.ComponentID -in @('ms_tcpip','ms_tcpip6')) { $protocols[$binding.ComponentID]=[bool]$binding.Enabled }
            }
            foreach ($component in @('ms_msclient','ms_server','ms_lldp','ms_lltdio','ms_rspndr')) {
                $current=OwnedAdapter
                if ($current.InterfaceDescription -cne $adapter.InterfaceDescription) { throw 'Owned Qeli adapter was replaced' }
                $bindings=@(Bindings $current | Where-Object { $_.ComponentID -eq $component })
                if ($bindings.Count -gt 1) { throw 'Ambiguous binding identity' }
                foreach ($binding in $bindings) {
                    if ($binding.InterfaceDescription -cne $current.InterfaceDescription) { throw 'Foreign binding rejected' }
                    if ($binding.Enabled) { Disable-NetAdapterBinding -InputObject $binding -Confirm:$false -ErrorAction Stop | Out-Null }
                }
            }
            $after=Bindings (OwnedAdapter)
            foreach ($binding in $after) {
                if ($binding.ComponentID -in @('ms_msclient','ms_server','ms_lldp','ms_lltdio','ms_rspndr') -and $binding.Enabled) { throw 'Sharing/discovery binding remained enabled' }
                if ($protocols.ContainsKey($binding.ComponentID) -and [bool]$binding.Enabled -ne $protocols[$binding.ComponentID]) { throw 'IP protocol binding changed unexpectedly' }
            }
            foreach ($component in $protocols.Keys) {
                $actual=@($after | Where-Object { $_.ComponentID -eq $component })
                if ($actual.Count -ne 1 -or [bool]$actual[0].Enabled -ne $protocols[$component]) { throw 'IP protocol binding disappeared or changed' }
            }
            [Console]::Out.Write('Owned adapter sharing bindings verified')
            """;
    }
}
