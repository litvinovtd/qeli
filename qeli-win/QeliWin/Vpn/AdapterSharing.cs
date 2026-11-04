using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
namespace QeliWin.Vpn;

internal static class AdapterSharing
{
    [DllImport("iphlpapi.dll")]
    private static extern uint ConvertInterfaceLuidToGuid(in ulong luid, out Guid guid);

    internal const int TimeoutMs = 30_000;

    internal static string DriverVersion(uint version) => version == 0
        ? "not loaded or unavailable" : $"{version >> 16}.{version & 0xffff} (kernel API; package patch version is not reported)";

    internal static void Apply(WintunAdapter adapter, CancellationToken cancellationToken, Action<string> log)
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
            Run(start, cancellationToken, log);
        });
    }

    // A separate budget: cold PowerShell/CIM startup is not a five-second route command.
    // Both pipes are drained continuously, with bounded tails retained even on timeout.
    internal static void Run(ProcessStartInfo start, CancellationToken cancellationToken,
        Action<string>? log = null, int timeoutMs = TimeoutMs)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(timeoutMs);
        cancellationToken.ThrowIfCancellationRequested();
        var clock = Stopwatch.StartNew();
        var gate = new object();
        var outputTail = new Queue<string>();
        var errorTail = new Queue<string>();
        string stage = "starting PowerShell";
        var stdoutDone = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var stderrDone = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        void Record(string? line, bool error)
        {
            if (line == null) { (error ? stderrDone : stdoutDone).TrySetResult(); return; }
            if (line.Length > 2048) line = line[..2048] + " [truncated]";
            lock (gate) {
                if (line.StartsWith("QELI_ADAPTER_STAGE ", StringComparison.Ordinal)) stage = line[19..];
                var tail = error ? errorTail : outputTail;
                tail.Enqueue((error ? "stderr: " : "stdout: ") + line);
                while (tail.Count > (error ? 16 : 8)) tail.Dequeue();
            }
            try { log?.Invoke($"Adapter sharing: elapsed={clock.ElapsedMilliseconds}ms {line}"); }
            catch { /* A log consumer must not crash the process output pump. */ }
        }
        string Evidence()
        {
            lock (gate) return $"stage={stage}; elapsed={clock.ElapsedMilliseconds}ms; budget={timeoutMs}ms; " +
                string.Join(" | ", outputTail.Concat(errorTail));
        }
        using var process = new Process { StartInfo = start };
        process.OutputDataReceived += (_, e) => Record(e.Data, false);
        process.ErrorDataReceived += (_, e) => Record(e.Data, true);
        string Stop()
        {
            try {
                if (!process.HasExited) process.Kill(entireProcessTree: true);
                return process.WaitForExit(2000) ? "" : "; child process did not exit after termination";
            } catch (Exception error) { return "; child termination failed: " + error.Message; }
        }
        void Drain() => Task.WhenAll(stdoutDone.Task, stderrDone.Task).Wait(1000);
        try {
            if (!process.Start()) throw new InvalidOperationException("PowerShell did not start");
        } catch (Exception error) {
            string native = error is Win32Exception win32 ? $"; win32={win32.NativeErrorCode}" : "";
            throw new InvalidOperationException($"Cannot start owned adapter sharing setup; type={error.GetType().Name}; hresult=0x{error.HResult:X8}{native}; {error.Message}; " + Evidence(), error);
        }
        try {
            process.BeginOutputReadLine();
            process.BeginErrorReadLine();
            while (!process.WaitForExit(50)) {
                cancellationToken.ThrowIfCancellationRequested();
                if (clock.ElapsedMilliseconds >= timeoutMs) {
                    string cleanup = Stop();
                    Drain();
                    throw new TimeoutException("Timed out configuring sharing/discovery on owned Qeli adapter; " + Evidence() + cleanup);
                }
            }
            Drain();
            cancellationToken.ThrowIfCancellationRequested();
            if (process.ExitCode != 0)
                throw new InvalidOperationException($"Owned adapter sharing setup failed (exit {process.ExitCode}); " + Evidence());
        } catch (OperationCanceledException) {
            string cleanup = Stop();
            Drain();
            throw new OperationCanceledException("Owned adapter sharing setup cancelled; " + Evidence() + cleanup, cancellationToken);
        } finally {
            if (!process.HasExited) Stop();
        }
    }

    // Microsoft NetAdapterBindingElementSetting links the exact CIM adapter to
    // its binding instances. No alias interpolation, wildcard lookup or blanket disable.
    // https://learn.microsoft.com/en-us/windows/win32/fwp/wmi/netadaptercimprov/msft-netadapterbindingelementsetting
    internal static string BuildScript(Guid guid)
    {
        if (guid == Guid.Empty) throw new ArgumentException("Adapter GUID is empty", nameof(guid));
        return "$ErrorActionPreference='Stop'; $expected=[guid]'" + guid.ToString("D") + "';" + """
            function Stage($name) {
                [Console]::Out.WriteLine('QELI_ADAPTER_STAGE ' + $name)
                [Console]::Out.Flush()
            }
            function OwnedAdapter {
                $ownedAdapters=@(Get-NetAdapter -IncludeHidden -ErrorAction Stop | Where-Object { [guid]$_.InterfaceGuid -eq $expected })
                if ($ownedAdapters.Count -ne 1) { throw 'Owned Qeli adapter identity is missing or ambiguous' }
                return $ownedAdapters[0]
            }
            function Bindings {
                param($adapter)
                return @(Get-CimAssociatedInstance -InputObject $adapter -Association MSFT_NetAdapterBindingElementSetting -ResultClassName MSFT_NetAdapterBindingSettingData -ErrorAction Stop)
            }
            try {
            Stage 'find-owned-adapter'
            $adapter=OwnedAdapter
            Stage 'read-bindings'
            $all=Bindings $adapter
            $protocols=@{}
            foreach ($binding in $all) {
                if ($binding.ComponentID -in @('ms_tcpip','ms_tcpip6')) { $protocols[$binding.ComponentID]=[bool]$binding.Enabled }
            }
            # Validate every target before the first mutation. Reuse the associated
            # CIM instances, not name/wildcard selectors or seven full CIM scans.
            $targets=@()
            foreach ($component in @('ms_msclient','ms_server','ms_lldp','ms_lltdio','ms_rspndr')) {
                $bindings=@($all | Where-Object { $_.ComponentID -eq $component })
                if ($bindings.Count -gt 1) { throw 'Ambiguous binding identity' }
                foreach ($binding in $bindings) {
                    if ($binding.InterfaceDescription -cne $adapter.InterfaceDescription) { throw 'Foreign binding rejected' }
                    if ($binding.Enabled) { $targets+= $binding }
                }
            }
            Stage 'verify-before-change'
            foreach ($binding in $targets) {
                $current=OwnedAdapter
                if ($current.InterfaceDescription -cne $adapter.InterfaceDescription) { throw 'Owned Qeli adapter was replaced' }
                Stage ('disable-' + $binding.ComponentID)
                Disable-NetAdapterBinding -InputObject $binding -Confirm:$false -ErrorAction Stop | Out-Null
            }
            Stage 'verify-readback'
            $current=OwnedAdapter
            if ($current.InterfaceDescription -cne $adapter.InterfaceDescription) { throw 'Owned Qeli adapter was replaced' }
            $after=Bindings $current
            foreach ($binding in $after) {
                if ($binding.ComponentID -in @('ms_msclient','ms_server','ms_lldp','ms_lltdio','ms_rspndr') -and $binding.Enabled) { throw 'Sharing/discovery binding remained enabled' }
                if ($protocols.ContainsKey($binding.ComponentID) -and [bool]$binding.Enabled -ne $protocols[$binding.ComponentID]) { throw 'IP protocol binding changed unexpectedly' }
            }
            foreach ($component in $protocols.Keys) {
                $actual=@($after | Where-Object { $_.ComponentID -eq $component })
                if ($actual.Count -ne 1 -or [bool]$actual[0].Enabled -ne $protocols[$component]) { throw 'IP protocol binding disappeared or changed' }
            }
            Stage 'verified'
            } catch {
                [Console]::Error.WriteLine(('QELI_ADAPTER_ERROR type={0}; hresult=0x{1:X8}; category={2}; id={3}; message={4}' -f $_.Exception.GetType().FullName,$_.Exception.HResult,$_.CategoryInfo.Category,$_.FullyQualifiedErrorId,$_.Exception.Message))
                [Console]::Error.Flush()
                throw
            }
            """;
    }
}
