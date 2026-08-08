using System.Diagnostics;
using System.Net;
using System.Text.Json;

namespace QeliMac.Vpn;

/// <summary>
/// Persistent ownership journal for the host-wide macOS DNS override.
///
/// <c>networksetup -setdnsservers</c> changes a physical network service, so process
/// teardown is not enough: SIGKILL or a native crash skips every finally/Dispose
/// block. The journal is created atomically <em>before</em> the DNS mutation and is removed
/// only after the exact previous resolver list has been restored. A later privileged qeli
/// process can therefore repair a stale override before it starts another tunnel.
/// </summary>
internal sealed class DnsJournal
{
    internal readonly record struct Owner(int Pid, long StartTicks);
    internal readonly record struct ReadResult(bool Ok, IReadOnlyList<string> Servers, string Error);
    internal readonly record struct WriteResult(bool Ok, string Error);

    internal enum RecoveryResult
    {
        NothingToDo,
        LiveOwner,
        Restored,
        AlreadyRestored,
        PreservedExternalChange,
        Failed,
    }

    private sealed class State
    {
        public int Version { get; set; } = 1;
        public string Service { get; set; } = "";
        public List<string> PreviousServers { get; set; } = new();
        public List<string> AppliedServers { get; set; } = new();
        public int OwnerPid { get; set; }
        public long OwnerStartTicks { get; set; }
    }

    private const int StateVersion = 1;
    private const long MaxStateBytes = 64 * 1024;
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    private readonly string _statePath;
    private readonly Func<string, ReadResult> _read;
    private readonly Func<string, IReadOnlyList<string>, WriteResult> _write;
    private readonly Func<Owner, bool> _ownerAlive;
    private readonly Owner _owner;
    private readonly Action<string> _log;

    internal DnsJournal(
        string statePath,
        Func<string, ReadResult> read,
        Func<string, IReadOnlyList<string>, WriteResult> write,
        Func<Owner, bool> ownerAlive,
        Owner owner,
        Action<string> log)
    {
        _statePath = statePath;
        _read = read;
        _write = write;
        _ownerAlive = ownerAlive;
        _owner = owner;
        _log = log;
    }

    /// <summary>
    /// Recover a dead owner's override, or leave a live owner's state untouched. This also
    /// handles the tiny prepare-before-apply crash window: when DNS still equals the saved
    /// previous value, only the now-unneeded journal is removed.
    /// </summary>
    internal RecoveryResult RecoverStale()
    {
        var state = ReadState(out var readError);
        if (state == null)
        {
            if (File.Exists(_statePath))
            {
                _log($"Cannot read stale DNS journal at {_statePath}: {readError}; " +
                     "leaving it in place so the original DNS is not lost");
                return RecoveryResult.Failed;
            }
            return RecoveryResult.NothingToDo;
        }

        var owner = new Owner(state.OwnerPid, state.OwnerStartTicks);
        if (owner == _owner)
        {
            // A clean-stop restore may fail transiently while the GUI/daemon process stays
            // alive. A later reconnect in that same process must retry the journal instead
            // of being blocked forever by its own still-live PID.
            _log("Found an unreleased DNS journal owned by this qeli process; retrying restore");
            return RestoreState(state);
        }
        if (_ownerAlive(owner))
        {
            _log($"DNS override is owned by live qeli process {owner.Pid}; leaving it unchanged");
            return RecoveryResult.LiveOwner;
        }

        _log($"Found stale DNS override from qeli process {owner.Pid}; recovering before connect");
        return RestoreState(state);
    }

    /// <summary>
    /// Atomically claim the host DNS, then apply <paramref name="servers"/>. The returned
    /// release action is the clean-stop path. It reloads the journal instead of trusting an
    /// in-memory snapshot, so failed restores remain recoverable by a later process.
    /// </summary>
    internal bool TryTakeOver(
        string service,
        IReadOnlyList<string> servers,
        out Action? release,
        out string? error)
    {
        release = null;
        error = null;

        var applied = Normalize(servers);
        if (applied.Count == 0)
        {
            error = "no valid resolver IPs were supplied";
            return false;
        }

        var recovery = RecoverStale();
        if (recovery is RecoveryResult.LiveOwner or RecoveryResult.Failed)
        {
            error = recovery == RecoveryResult.LiveOwner
                ? "another live qeli process owns the system DNS override"
                : $"the stale DNS journal at {_statePath} could not be recovered";
            return false;
        }

        var before = _read(service);
        if (!before.Ok)
        {
            error = $"could not capture the existing DNS for \"{service}\": {before.Error}";
            return false;
        }

        var state = new State
        {
            Version = StateVersion,
            Service = service,
            PreviousServers = Normalize(before.Servers),
            AppliedServers = applied,
            OwnerPid = _owner.Pid,
            OwnerStartTicks = _owner.StartTicks,
        };

        if (!TryCreateState(state, out var stateError))
        {
            error = $"could not create the DNS recovery journal: {stateError}";
            return false;
        }

        var appliedResult = _write(service, applied);
        if (!appliedResult.Ok)
        {
            // networksetup may have changed the service even when it returned a failure.
            // Use the just-persisted journal to verify and roll back instead of assuming it
            // was a no-op. If rollback fails, the journal intentionally remains for startup.
            var rollback = RestoreOwned(_owner);
            error = $"networksetup could not apply DNS to \"{service}\": {appliedResult.Error}" +
                    (rollback == RecoveryResult.Failed
                        ? $"; rollback also failed, recovery state kept at {_statePath}"
                        : "");
            return false;
        }

        bool released = false;
        release = () =>
        {
            if (released) return;
            released = true;
            RestoreOwned(_owner);
        };
        return true;
    }

    private RecoveryResult RestoreOwned(Owner expectedOwner)
    {
        var state = ReadState(out var readError);
        if (state == null)
        {
            if (File.Exists(_statePath))
            {
                _log($"Cannot read DNS journal during restore: {readError}; keeping it for retry");
                return RecoveryResult.Failed;
            }
            return RecoveryResult.NothingToDo;
        }

        if (state.OwnerPid != expectedOwner.Pid || state.OwnerStartTicks != expectedOwner.StartTicks)
        {
            _log("DNS journal ownership changed; refusing to restore another qeli process's state");
            return RecoveryResult.LiveOwner;
        }
        return RestoreState(state);
    }

    private RecoveryResult RestoreState(State state)
    {
        var currentResult = _read(state.Service);
        if (!currentResult.Ok)
        {
            _log($"Could not inspect current DNS on \"{state.Service}\" while restoring: " +
                 $"{currentResult.Error}; journal kept at {_statePath}");
            return RecoveryResult.Failed;
        }

        var current = Normalize(currentResult.Servers);
        if (SameServers(current, state.PreviousServers))
        {
            // Crash after the journal rename but before networksetup, or an earlier restore
            // succeeded and the process died before deleting the journal.
            if (!DeleteState(out var deleteError))
            {
                _log($"DNS was already restored but its journal could not be removed: {deleteError}");
                return RecoveryResult.Failed;
            }
            _log($"DNS on \"{state.Service}\" was already at its pre-qeli value; stale journal removed");
            return RecoveryResult.AlreadyRestored;
        }

        if (!SameServers(current, state.AppliedServers))
        {
            // The user, DHCP/network management software, or another VPN changed DNS after
            // qeli died. Restoring our older snapshot would clobber that newer decision.
            if (!DeleteState(out var deleteError))
            {
                _log($"DNS was changed outside qeli and its stale journal could not be removed: {deleteError}");
                return RecoveryResult.Failed;
            }
            _log($"DNS on \"{state.Service}\" no longer matches qeli's override; " +
                 "preserving the external change and discarding the stale journal");
            return RecoveryResult.PreservedExternalChange;
        }

        var restored = _write(state.Service, state.PreviousServers);
        if (!restored.Ok)
        {
            _log($"Failed to restore DNS on \"{state.Service}\": {restored.Error}; " +
                 $"journal kept at {_statePath} for the next qeli start");
            return RecoveryResult.Failed;
        }
        if (!DeleteState(out var removeError))
        {
            _log($"DNS restored on \"{state.Service}\", but the journal could not be removed: {removeError}");
            return RecoveryResult.Failed;
        }

        _log($"Restored DNS on \"{state.Service}\" to its pre-qeli value");
        return RecoveryResult.Restored;
    }

    private State? ReadState(out string error)
    {
        error = "";
        try
        {
            if (!File.Exists(_statePath)) return null;
            var info = new FileInfo(_statePath);
            if (info.Length is <= 0 or > MaxStateBytes)
                throw new InvalidDataException($"invalid journal size {info.Length}");

            var state = JsonSerializer.Deserialize<State>(File.ReadAllText(_statePath), JsonOptions)
                        ?? throw new InvalidDataException("empty journal");
            Validate(state);
            return state;
        }
        catch (Exception ex)
        {
            error = ex.Message;
            return null;
        }
    }

    private bool TryCreateState(State state, out string error)
    {
        error = "";
        string? dir = Path.GetDirectoryName(_statePath);
        string temp = _statePath + $".{_owner.Pid}.{Guid.NewGuid():N}.tmp";
        try
        {
            if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
            using (var fs = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                if (!OperatingSystem.IsWindows())
                    File.SetUnixFileMode(temp, UnixFileMode.UserRead | UnixFileMode.UserWrite);
                JsonSerializer.Serialize(fs, state, JsonOptions);
                fs.Flush(flushToDisk: true);
            }
            // No overwrite: this rename is also the inter-process acquisition primitive.
            // If another qeli instance won the race, its recovery state remains untouched.
            File.Move(temp, _statePath, overwrite: false);
            return true;
        }
        catch (Exception ex)
        {
            error = ex.Message;
            return false;
        }
        finally
        {
            try { if (File.Exists(temp)) File.Delete(temp); } catch { }
        }
    }

    private bool DeleteState(out string error)
    {
        error = "";
        try
        {
            File.Delete(_statePath);
            return true;
        }
        catch (Exception ex)
        {
            error = ex.Message;
            return false;
        }
    }

    private static void Validate(State state)
    {
        if (state.Version != StateVersion) throw new InvalidDataException($"unsupported version {state.Version}");
        if (string.IsNullOrWhiteSpace(state.Service) || state.Service.Length > 256 || state.Service.Contains('\0'))
            throw new InvalidDataException("invalid network service name");
        if (state.OwnerPid <= 0 || state.OwnerStartTicks <= 0)
            throw new InvalidDataException("invalid owner identity");
        if (state.PreviousServers.Count > 16 || state.AppliedServers.Count is <= 0 or > 16)
            throw new InvalidDataException("invalid DNS server count");
        if (Normalize(state.PreviousServers).Count != state.PreviousServers.Count ||
            Normalize(state.AppliedServers).Count != state.AppliedServers.Count)
            throw new InvalidDataException("invalid or duplicate DNS server address");
    }

    private static List<string> Normalize(IEnumerable<string> servers)
    {
        var result = new List<string>();
        foreach (var raw in servers)
        {
            if (!IPAddress.TryParse(raw.Trim(), out var ip)) continue;
            string canonical = ip.ToString();
            if (!result.Contains(canonical, StringComparer.OrdinalIgnoreCase)) result.Add(canonical);
        }
        return result;
    }

    private static bool SameServers(IReadOnlyList<string> left, IReadOnlyList<string> right) =>
        left.Count == right.Count && left.Zip(right).All(p =>
            string.Equals(p.First, p.Second, StringComparison.OrdinalIgnoreCase));

    internal static Owner CurrentOwner()
    {
        using var process = Process.GetCurrentProcess();
        return new Owner(process.Id, process.StartTime.Ticks);
    }

    internal static bool IsOwnerAlive(Owner owner)
    {
        try
        {
            using var process = Process.GetProcessById(owner.Pid);
            return process.StartTime.Ticks == owner.StartTicks && !process.HasExited;
        }
        catch { return false; }
    }

    /// <summary>Pure fake-network regression coverage, invoked by <c>QeliMac selftest</c>.</summary>
    internal static void RunSelfTests(Action<string, bool> check)
    {
        string dir = Path.Combine(Path.GetTempPath(), $"qeli-dns-journal-{Guid.NewGuid():N}");
        Directory.CreateDirectory(dir);
        try
        {
            // SIGKILL after apply: the next owner restores the exact previous DNS.
            var current = new Dictionary<string, List<string>> { ["Wi-Fi"] = new() { "192.168.1.1" } };
            var live = new HashSet<Owner>();
            ReadResult Read(string service) => new(true, current[service].ToList(), "");
            WriteResult Write(string service, IReadOnlyList<string> value)
            {
                current[service] = value.ToList();
                return new(true, "");
            }

            var oldOwner = new Owner(100, 1000);
            live.Add(oldOwner);
            var first = new DnsJournal(Path.Combine(dir, "crash.json"), Read, Write,
                live.Contains, oldOwner, _ => { });
            bool acquired = first.TryTakeOver("Wi-Fi", new[] { "10.9.0.1" }, out _, out _);
            live.Remove(oldOwner); // simulated SIGKILL
            var next = new DnsJournal(Path.Combine(dir, "crash.json"), Read, Write,
                live.Contains, new Owner(200, 2000), _ => { });
            var recovered = next.RecoverStale();
            check("DNS journal restores after a crashed owner",
                acquired && recovered == RecoveryResult.Restored &&
                current["Wi-Fi"].SequenceEqual(new[] { "192.168.1.1" }) &&
                !File.Exists(Path.Combine(dir, "crash.json")));

            // DHCP/no explicit DNS is represented by networksetup's `empty` value and must
            // not turn into a hard-coded public resolver after recovery.
            current["Wi-Fi"] = new();
            live.Add(oldOwner);
            var dhcpPath = Path.Combine(dir, "dhcp.json");
            var dhcp = new DnsJournal(dhcpPath, Read, Write, live.Contains, oldOwner, _ => { });
            bool dhcpAcquired = dhcp.TryTakeOver("Wi-Fi", new[] { "10.9.0.1" }, out _, out _);
            live.Remove(oldOwner);
            var dhcpRecovery = new DnsJournal(dhcpPath, Read, Write, live.Contains,
                new Owner(202, 2002), _ => { }).RecoverStale();
            check("DNS journal restores DHCP/automatic DNS after a crash",
                dhcpAcquired && dhcpRecovery == RecoveryResult.Restored &&
                current["Wi-Fi"].Count == 0 && !File.Exists(dhcpPath));

            // A post-crash manual/system change wins over the older saved snapshot.
            current["Wi-Fi"] = new() { "192.168.1.1" };
            live.Add(oldOwner);
            var manualPath = Path.Combine(dir, "manual.json");
            var manual = new DnsJournal(manualPath, Read, Write, live.Contains, oldOwner, _ => { });
            bool manualAcquired = manual.TryTakeOver("Wi-Fi", new[] { "10.9.0.1" }, out _, out _);
            live.Remove(oldOwner);
            current["Wi-Fi"] = new() { "9.9.9.9" };
            var manualRecovery = new DnsJournal(manualPath, Read, Write, live.Contains,
                new Owner(201, 2001), _ => { }).RecoverStale();
            check("DNS journal preserves a newer external DNS change",
                manualAcquired && manualRecovery == RecoveryResult.PreservedExternalChange &&
                current["Wi-Fi"].SequenceEqual(new[] { "9.9.9.9" }) && !File.Exists(manualPath));

            // A second qeli process must not steal or roll back a live tunnel's DNS.
            current["Wi-Fi"] = new() { "192.168.1.1" };
            live.Add(oldOwner);
            var livePath = Path.Combine(dir, "live.json");
            var ownerJournal = new DnsJournal(livePath, Read, Write, live.Contains, oldOwner, _ => { });
            bool ownerAcquired = ownerJournal.TryTakeOver("Wi-Fi", new[] { "10.9.0.1" }, out var release, out _);
            var contender = new DnsJournal(livePath, Read, Write, live.Contains,
                new Owner(300, 3000), _ => { });
            bool contenderAcquired = contender.TryTakeOver("Wi-Fi", new[] { "10.9.0.2" }, out _, out _);
            check("DNS journal does not override a live qeli owner",
                ownerAcquired && !contenderAcquired &&
                current["Wi-Fi"].SequenceEqual(new[] { "10.9.0.1" }));
            release?.Invoke();
            live.Remove(oldOwner);

            // A transient restore failure must be retryable without restarting the GUI.
            current["Wi-Fi"] = new() { "192.168.1.1" };
            live.Add(oldOwner);
            bool failNextRestore = false;
            WriteResult FlakyWrite(string service, IReadOnlyList<string> value)
            {
                if (failNextRestore && value.SequenceEqual(new[] { "192.168.1.1" }))
                {
                    failNextRestore = false;
                    return new(false, "injected transient failure");
                }
                current[service] = value.ToList();
                return new(true, "");
            }
            var retryPath = Path.Combine(dir, "retry.json");
            var retry = new DnsJournal(retryPath, Read, FlakyWrite, live.Contains, oldOwner, _ => { });
            bool retryAcquired = retry.TryTakeOver("Wi-Fi", new[] { "10.9.0.1" }, out var retryRelease, out _);
            failNextRestore = true;
            retryRelease?.Invoke();
            bool journalKept = File.Exists(retryPath);
            bool reacquired = retry.TryTakeOver("Wi-Fi", new[] { "10.9.0.2" }, out var finalRelease, out _);
            check("DNS journal retries a failed restore in the same process",
                retryAcquired && journalKept && reacquired &&
                current["Wi-Fi"].SequenceEqual(new[] { "10.9.0.2" }));
            finalRelease?.Invoke();
            live.Remove(oldOwner);
        }
        finally
        {
            try { Directory.Delete(dir, recursive: true); } catch { }
        }
    }
}
