using System.Diagnostics;
using System.IO;
using System.Net;
using System.Text;
using System.Text.Json;

namespace QeliWin.Vpn;

/// <summary>Write-ahead recovery of the session's L3 settings on the owned device.
/// No physical interface is selected; pre-existing addresses/routes are not removed.</summary>
internal static class PersistentWintunNetwork
{
    internal sealed record Address(string Ip,int Prefix);
    internal sealed record Route(string Cidr,string NextHop,int Metric);
    internal sealed record Snapshot
    {
        public Address[] Addresses {get;init;}=[];
        public Route[] Routes {get;init;}=[];
        public string Dns4 {get;init;}="";
        public string Dns6 {get;init;}="";
    }
    internal sealed record State
    {
        public Guid InterfaceGuid {get;init;}
        public Snapshot Before {get;init;}=new();
        public Address[] Addresses {get;init;}=[];
        public Route[] Routes {get;init;}=[];
        public string[] Dns {get;init;}=[];
    }

    internal static void Validate(State state,Guid expected)
    {
        if(expected==Guid.Empty || state.InterfaceGuid!=expected || state.Before==null
            || state.Addresses==null || state.Routes==null || state.Dns==null
            || state.Before.Addresses==null || state.Before.Routes==null
            || state.Addresses.Length>32 || state.Before.Addresses.Length>1024
            || state.Routes.Length>65536 || state.Before.Routes.Length>65536 || state.Dns.Length>16)
            throw new InvalidDataException("Invalid persistent network recovery state");
        foreach(var address in state.Addresses.Concat(state.Before.Addresses))
            if(address==null || !IPAddress.TryParse(address.Ip,out var ip)
                || address.Prefix<0 || address.Prefix>(ip.AddressFamily==System.Net.Sockets.AddressFamily.InterNetwork?32:128))
                throw new InvalidDataException("Invalid persistent recovery address");
        foreach(var route in state.Routes.Concat(state.Before.Routes))
        {
            if(route==null || route.Cidr==null || route.NextHop==null || route.Metric<0)
                throw new InvalidDataException("Invalid persistent recovery route");
            var pieces=route.Cidr.Split('/');
            if(pieces.Length!=2 || !IPAddress.TryParse(pieces[0],out var ip)
                || !int.TryParse(pieces[1],out int prefix) || prefix<0
                || prefix>(ip.AddressFamily==System.Net.Sockets.AddressFamily.InterNetwork?32:128)
                || !IPAddress.TryParse(route.NextHop,out var next) || next.AddressFamily!=ip.AddressFamily)
                throw new InvalidDataException("Invalid persistent recovery route");
        }
        foreach(var raw in state.Dns.Concat(new[]{state.Before.Dns4,state.Before.Dns6}))
        {
            if(raw==null || raw.Length>2048) throw new InvalidDataException("Invalid persistent DNS recovery state");
            foreach(var text in raw.Split([',',' ',';','\t'],StringSplitOptions.RemoveEmptyEntries))
                if(!IPAddress.TryParse(text,out _)) throw new InvalidDataException("Invalid persistent DNS recovery address");
        }
    }

    internal static void Begin(PersistentWintunDevice.Lease lease,IEnumerable<Address> addresses,
        IEnumerable<Route> routes,IReadOnlyList<string> dns,Func<ProcessStartInfo,string,string> run)
    {
        lease.Verify();
        if(lease.Record.Network!=null) throw new InvalidOperationException("Recover the preceding persistent network plan first");
        var output=run(Start(CaptureScript(lease.Record.InterfaceGuid)),"snapshot owned persistent Wintun L3 settings");
        if(output.Length>4*1024*1024) throw new InvalidDataException("Persistent adapter snapshot is too large");
        var before=JsonSerializer.Deserialize<Snapshot>(output) ?? throw new InvalidDataException("Missing persistent adapter snapshot");
        var state=new State {InterfaceGuid=lease.Record.InterfaceGuid,Before=before,
            Addresses=addresses.Distinct().ToArray(),Routes=routes.Select(CanonicalRoute).Distinct().ToArray(),Dns=dns.ToArray()};
        Validate(state,lease.Record.InterfaceGuid);
        // Same-address/different-prefix is not safe to overwrite or silently adopt.
        foreach(var address in state.Addresses)
            if(before.Addresses.Any(a=>IPAddress.Parse(a.Ip).Equals(IPAddress.Parse(address.Ip)) && a.Prefix!=address.Prefix))
                throw new InvalidOperationException("Persistent adapter has a conflicting pre-existing address prefix");
        lease.SaveNetwork(state); // Durable before the first IP/DNS/route mutation.
    }

    internal static void Recover(PersistentWintunDevice.Lease lease,Func<ProcessStartInfo,string,string> run)
    {
        if(lease.Record.Network is not { } state) return;
        Validate(state,lease.Record.InterfaceGuid);lease.Verify();
        _=run(Start(RestoreScript(state,lease.RecoveryPath)),"restore owned persistent Wintun L3 settings");
        lease.Verify();
        lease.SaveNetwork(null); // Never clear ownership after failed/partial rollback.
    }

    internal static bool WasAddressPresent(State state,string ip,int prefix) =>
        state.Before.Addresses.Any(a=>IPAddress.Parse(a.Ip).Equals(IPAddress.Parse(ip)) && a.Prefix==prefix);

    private static Route CanonicalRoute(Route route)
    {
        var parts=route.Cidr.Split('/');
        if(parts.Length!=2 || !IPAddress.TryParse(parts[0],out var address) || !int.TryParse(parts[1],out int prefix))
            throw new InvalidDataException("Invalid persistent route prefix");
        var bytes=address.GetAddressBytes();
        if(prefix<0 || prefix>bytes.Length*8) throw new InvalidDataException("Invalid persistent route length");
        for(int i=0;i<bytes.Length;i++) {
            int bits=Math.Clamp(prefix-i*8,0,8);bytes[i]&=(byte)(0xff<<(8-bits));
        }
        return route with {Cidr=new IPAddress(bytes)+"/"+prefix,NextHop=IPAddress.Parse(route.NextHop).ToString()};
    }

    internal static ProcessStartInfo Start(string script)
    {
        string encoded=Convert.ToBase64String(Encoding.Unicode.GetBytes(script));
        if(encoded.Length>30_000) throw new InvalidOperationException("Persistent recovery command exceeds Windows command-line budget; use its protected data file");
        var start=new ProcessStartInfo(SystemPaths.PowerShell) {UseShellExecute=false,
            RedirectStandardOutput=true,RedirectStandardError=true,CreateNoWindow=true,WorkingDirectory=SystemPaths.SystemDirectory};
        foreach(var argument in new[]{"-NoLogo","-NoProfile","-NonInteractive","-EncodedCommand",encoded})
            start.ArgumentList.Add(argument);
        return start;
    }

    private static string Header(Guid guid) => "$ErrorActionPreference='Stop'; $expected=[guid]'"+guid.ToString("D")+"';"+"""
        function Owned {
            $found=@(Get-NetAdapter -IncludeHidden -ErrorAction Stop | Where-Object {[guid]$_.InterfaceGuid -eq $expected})
            if($found.Count -ne 1) {throw 'Persistent adapter GUID is missing or ambiguous'}
            return $found[0]
        }
        function Addresses {
            $a=Owned
            return @(Get-NetIPAddress -PolicyStore ActiveStore -ErrorAction Stop | Where-Object {$_.InterfaceIndex -eq $a.ifIndex} | ForEach-Object {
                [pscustomobject]@{Ip=[string]$_.IPAddress;Prefix=[int]$_.PrefixLength}
            })
        }
        function Routes {
            $a=Owned
            return @(Get-NetRoute -PolicyStore ActiveStore -ErrorAction Stop | Where-Object {$_.InterfaceIndex -eq $a.ifIndex} | ForEach-Object {
                [pscustomobject]@{Cidr=[string]$_.DestinationPrefix;NextHop=[string]$_.NextHop;Metric=[int]$_.RouteMetric}
            })
        }
        function DnsRaw {
            param([string]$family)
            $path='HKLM:\SYSTEM\CurrentControlSet\Services\'+$family+'\Parameters\Interfaces\'+$expected.ToString('B')
            if(-not (Test-Path -LiteralPath $path)) {return ''}
            $value=Get-ItemProperty -LiteralPath $path -ErrorAction Stop
            if($value.PSObject.Properties['NameServer']) {return [string]$value.NameServer}
            return ''
        }
        function DnsList {
            param([string]$raw)
            return @($raw -split '[,;\s]+' | Where-Object {$_} | ForEach-Object {([ipaddress]$_).ToString()})
        }
        """;

    internal static string CaptureScript(Guid guid) => Header(guid)+"""
        $snapshot=[pscustomobject]@{Addresses=@(Addresses);Routes=@(Routes);Dns4=(DnsRaw 'Tcpip');Dns6=(DnsRaw 'Tcpip6')}
        $snapshot | ConvertTo-Json -Depth 8 -Compress
        """;

    internal static string RestoreScript(State state,string? recoveryPath=null)
    {
        Validate(state,state.InterfaceGuid);
        string read = recoveryPath is null
            ? "$state=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('"+Convert.ToBase64String(JsonSerializer.SerializeToUtf8Bytes(state))+"')) | ConvertFrom-Json;"
            : "$file='"+recoveryPath.Replace("'","''")+"'; if((Get-Item -LiteralPath $file -ErrorAction Stop).Length -gt 4194304) {throw 'Recovery file too large'}; $state=(Get-Content -LiteralPath $file -Raw -Encoding UTF8 -ErrorAction Stop | ConvertFrom-Json).Network; if(-not $state -or [guid]$state.InterfaceGuid -ne $expected) {throw 'Recovery identity mismatch'};";
        string exe=SystemPaths.Resolve("netsh").Replace("'","''");
        return Header(state.InterfaceGuid)+read+"$netsh='"+exe+"';"+"""
            function RouteKey {param($r) return ($r.Cidr+'|'+([ipaddress]$r.NextHop).ToString()+'|'+$r.Metric)}
            function AddressKey {param($a) return (([ipaddress]$a.Ip).ToString()+'/'+$a.Prefix)}
            $oldRoutes=@{}; foreach($r in $state.Before.Routes) {$oldRoutes[(RouteKey $r)]=$true}
            $wantedRoutes=@{}; foreach($r in $state.Routes) {$wantedRoutes[(RouteKey $r)]=$true}
            $oldAddresses=@{}; foreach($a in $state.Before.Addresses) {$oldAddresses[(AddressKey $a)]=$true}
            $wantedAddresses=@{}; foreach($a in $state.Addresses) {$wantedAddresses[(AddressKey $a)]=$true}
            $a=Owned
            foreach($r in @(Get-NetRoute -PolicyStore ActiveStore -ErrorAction Stop | Where-Object {$_.InterfaceIndex -eq $a.ifIndex})) {
                $key=RouteKey ([pscustomobject]@{Cidr=[string]$r.DestinationPrefix;NextHop=[string]$r.NextHop;Metric=[int]$r.RouteMetric})
                if($wantedRoutes.ContainsKey($key) -and -not $oldRoutes.ContainsKey($key) -and [string]$r.Protocol -in @('NetMgmt','NTStatic','NTStaticNonDOD')) {
                    if((Owned).ifIndex -ne $a.ifIndex) {throw 'Persistent interface changed'}
                    $r | Remove-NetRoute -Confirm:$false -ErrorAction Stop
                }
            }
            foreach($ip in @(Get-NetIPAddress -PolicyStore ActiveStore -ErrorAction Stop | Where-Object {$_.InterfaceIndex -eq $a.ifIndex})) {
                $key=AddressKey ([pscustomobject]@{Ip=[string]$ip.IPAddress;Prefix=[int]$ip.PrefixLength})
                if($wantedAddresses.ContainsKey($key) -and -not $oldAddresses.ContainsKey($key)) {
                    if((Owned).ifIndex -ne $a.ifIndex) {throw 'Persistent interface changed'}
                    $ip | Remove-NetIPAddress -Confirm:$false -ErrorAction Stop
                }
            }
            foreach($family in @('ipv4','ipv6')) {
                $v6=$family -eq 'ipv6'; $registry=if($v6){'Tcpip6'}else{'Tcpip'}
                $before=if($v6){[string]$state.Before.Dns6}else{[string]$state.Before.Dns4}
                $desired=@($state.Dns | Where-Object {(([ipaddress]$_).AddressFamily -eq 'InterNetworkV6') -eq $v6})
                if($desired.Count -eq 0) {continue}
                $current=@(DnsList (DnsRaw $registry)); $old=@(DnsList $before)
                if(($current -join ',') -eq ($old -join ',')) {continue}
                # Normal net cleanup has already reset our DNS to DHCP; a crash may
                # instead leave all or a prefix of the desired static DNS list.
                $ours=$current.Count -eq 0
                if($current.Count -gt 0 -and $current.Count -le $desired.Count) {
                    $ours=($current -join ',') -eq (($desired | Select-Object -First $current.Count) -join ',')
                }
                if(-not $ours) {continue} # Preserve a distinct administrator edit.
                $index=(Owned).ifIndex
                if($old.Count -eq 0) { & $netsh interface $family set dnsservers "name=$index" source=dhcp | Out-Null }
                else {
                    & $netsh interface $family set dnsservers "name=$index" source=static "address=$($old[0])" validate=no | Out-Null
                }
                if($LASTEXITCODE -ne 0) {throw 'Persistent DNS restore failed'}
                for($i=1;$i -lt $old.Count;$i++) {
                    & $netsh interface $family add dnsservers "name=$index" "address=$($old[$i])" "index=$($i+1)" validate=no | Out-Null
                    if($LASTEXITCODE -ne 0) {throw 'Persistent secondary DNS restore failed'}
                }
                if(((DnsList (DnsRaw $registry)) -join ',') -ne ($old -join ',')) {throw 'Persistent DNS restore readback failed'}
            }
            foreach($r in @(Routes)) {
                $key=RouteKey $r
                if($wantedRoutes.ContainsKey($key) -and -not $oldRoutes.ContainsKey($key)) {throw 'Persistent route cleanup readback failed'}
            }
            foreach($ip in @(Addresses)) {
                $key=AddressKey $ip
                if($wantedAddresses.ContainsKey($key) -and -not $oldAddresses.ContainsKey($key)) {throw 'Persistent address cleanup readback failed'}
            }
            [Console]::Out.Write('Persistent adapter L3 recovery verified')
            """;
    }
}
