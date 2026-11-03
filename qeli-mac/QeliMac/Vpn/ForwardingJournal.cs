using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Runtime.InteropServices;
using QeliMac.Service;

namespace QeliMac.Vpn;

/// <summary>One cooperating Qeli forwarding owner per host; durable undo before sysctl.</summary>
internal sealed class ForwardingJournal(Func<byte[]?> readState, Func<byte[], bool, bool> writeState,
    Action deleteState, Func<string, bool> readFlag, Action<string, bool> writeFlag,
    Func<DnsJournal.Owner, bool> ownerAlive, DnsJournal.Owner self, string token,
    Func<IDisposable> acquireOperation, Action<string> log)
{
    internal const int MaximumBytes = 4096;
    private bool _owned;
    private bool _nativeAttempted;
    private bool _restoredConfirmed;
    internal bool Owned => _owned;
    private sealed class Family {
        public required string Name { get; init; }
        public required bool WasOn { get; init; }
        public required bool Pending { get; set; }
    }
    private sealed class State {
        public required int Version { get; init; }
        public required int Pid { get; init; }
        public required long StartTicks { get; init; }
        public required string Token { get; init; }
        public required List<Family> Families { get; init; }
    }
    private static readonly JsonSerializerOptions Options = new() {
        WriteIndented = true, UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow
    };

    internal static ForwardingJournal Create(Action<string> log) => new(
        () => ServiceState.ReadProtected("forwarding-state.json", MaximumBytes),
        (bytes, replace) => ServiceState.WriteProtected("forwarding-state.json", bytes, replace),
        () => ServiceState.DeleteProtected("forwarding-state.json"), ReadKernelFlag, WriteKernelFlag,
        OwnerAlive, CurrentOwner(), Guid.NewGuid().ToString("N"),
        () => ServiceState.EnterOperation("forwarding.lock"), log);

    internal static DnsJournal.Owner CurrentOwner() {
        using var process = System.Diagnostics.Process.GetCurrentProcess();
        return new(process.Id, process.StartTime.ToUniversalTime().Ticks);
    }
    internal static bool OwnerAlive(DnsJournal.Owner owner) {
        try {
            using var process = System.Diagnostics.Process.GetProcessById(owner.Pid);
            return !process.HasExited && process.StartTime.ToUniversalTime().Ticks == owner.StartTicks;
        }
        catch (ArgumentException) { return false; }
        catch { return true; } // Unknown is not proof of death.
    }

    [DllImport("libc")] private static extern uint geteuid();
    internal static void Sweep(Action<string> log) {
        if (!OperatingSystem.IsMacOS() || geteuid() != 0) return;
        Create(log).RecoverStale();
    }

    internal void Enable(bool ipv4, bool ipv6) {
        if (!ipv4 && !ipv6) throw new ArgumentException("Forwarding requires an active family");
        using var operation = acquireOperation();
        var names = new List<string>(); if (ipv4) names.Add("ipv4"); if (ipv6) names.Add("ipv6");
        var state = Read();
        if (state is not null) {
            if (IsSelf(state)) {
                _owned = true;
                _nativeAttempted |= state.Families.Any(f => f.Pending);
                if (!state.Families.Select(f => f.Name).SequenceEqual(names) || state.Families.Any(f => !readFlag(f.Name)))
                    throw new InvalidOperationException("Existing forwarding ownership requires cleanup before reconfiguration");
                return; // Never replace the saved pre-Qeli values with our already-enabled values.
            }
            if (ownerAlive(new(state.Pid, state.StartTicks))) throw new IOException("Another live Qeli forwarding owner exists");
            Cleanup(state);
        }
        // Observe every requested family before publishing or changing any kernel flag.
        state = new() { Version = 1, Pid = self.Pid, StartTicks = self.StartTicks, Token = token,
            Families = names.Select(n => { bool on = readFlag(n); return new Family { Name = n, WasOn = on, Pending = !on }; }).ToList() };
        Validate(state);
        _restoredConfirmed = false;
        _owned = true; // Publication errors may have an unknown outcome; keep retry responsibility.
        try {
            if (!writeState(JsonSerializer.SerializeToUtf8Bytes(state, Options), false)) {
                _owned = false; throw new IOException("Forwarding journal already exists");
            }
            foreach (var family in state.Families.Where(f => f.Pending)) {
                _nativeAttempted = true;
                writeFlag(family.Name, true);
                if (!readFlag(family.Name)) throw new IOException("Forwarding enable was not confirmed: " + family.Name);
            }
            Note("IP forwarding enabled/preserved for " + string.Join(",", names) + "; durable owner recorded");
        }
        catch (Exception setupError) {
            if (_owned) {
                try { ReleaseLocked(); }
                catch (Exception rollbackError) { throw new AggregateException("Forwarding setup and rollback failed", setupError, rollbackError); }
            }
            throw;
        }
    }

    internal void ReleaseOwned() {
        if (!_owned) return;
        using var operation = acquireOperation();
        ReleaseLocked();
    }
    private void ReleaseLocked() {
        var state = Read();
        if (state is null) {
            if (!_nativeAttempted || _restoredConfirmed) { ClearOwnership(); return; } // No kernel mutation ever attempted.
            throw new IOException("Owned forwarding journal disappeared; cleanup is unknown");
        }
        if (!IsSelf(state)) {
            if (_restoredConfirmed) { ClearOwnership(); return; } // A new owner after completed restore is preserved.
            throw new IOException("Cannot release a different forwarding generation");
        }
        Cleanup(state); ClearOwnership();
    }
    internal bool RecoverStale() {
        using var operation = acquireOperation();
        var state = Read();
        if (state is null || ownerAlive(new(state.Pid, state.StartTicks))) return false;
        Cleanup(state); return true;
    }
    private bool IsSelf(State state) => state.Pid == self.Pid && state.StartTicks == self.StartTicks && state.Token == token;
    private void Cleanup(State state) {
        var failures = new List<Exception>();
        foreach (var family in state.Families.Where(f => f.Pending)) {
            try {
                if (readFlag(family.Name)) {
                    writeFlag(family.Name, false);
                    if (readFlag(family.Name)) throw new IOException("Forwarding restore was not confirmed: " + family.Name);
                }
                family.Pending = false;
                if (!writeState(JsonSerializer.SerializeToUtf8Bytes(state, Options), true)) throw new IOException("Cannot checkpoint forwarding cleanup");
            }
            catch (Exception error) { failures.Add(error); }
        }
        if (failures.Count > 0) throw new AggregateException("Forwarding cleanup remains pending", failures);
        if (IsSelf(state)) _restoredConfirmed = true;
        deleteState(); // A failed deletion retains the completed journal or proven restore progress.
        Note("Forwarding restoration confirmed; recovery journal removed");
    }
    private void ClearOwnership() { _owned = false; _nativeAttempted = false; _restoredConfirmed = false; }
    private void Note(string message) { try { log(message); } catch { /* Observer failure cannot undo committed cleanup. */ } }
    private State? Read() {
        var bytes = readState(); if (bytes is null) return null;
        if (bytes.Length is 0 or > MaximumBytes) throw new InvalidDataException("Invalid forwarding journal size");
        string text = new UTF8Encoding(false, true).GetString(bytes);
        using var document = JsonDocument.Parse(text, new JsonDocumentOptions { MaxDepth = 8 });
        RequireUniqueFields(document.RootElement);
        var state = JsonSerializer.Deserialize<State>(text, Options)
            ?? throw new InvalidDataException("Empty forwarding journal");
        Validate(state); return state;
    }
    private static void RequireUniqueFields(JsonElement value) {
        if (value.ValueKind == JsonValueKind.Object) {
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var field in value.EnumerateObject()) {
                if (!names.Add(field.Name)) throw new InvalidDataException("Duplicate forwarding journal field");
                RequireUniqueFields(field.Value);
            }
        }
        else if (value.ValueKind == JsonValueKind.Array)
            foreach (var item in value.EnumerateArray()) RequireUniqueFields(item);
    }
    private static void Validate(State state) {
        if (state.Version != 1 || state.Pid <= 0 || state.StartTicks <= 0 || state.StartTicks > DateTime.MaxValue.Ticks
            || !Guid.TryParseExact(state.Token, "N", out var id) || id.ToString("N") != state.Token
            || state.Families is null || state.Families.Count is < 1 or > 2
            || state.Families.Any(f => f is null || f.Name is not ("ipv4" or "ipv6") || f.WasOn && f.Pending)
            || state.Families.Select(f => f.Name).Distinct(StringComparer.Ordinal).Count() != state.Families.Count)
            throw new InvalidDataException("Invalid forwarding ownership/restore metadata");
    }
    private static string KernelName(string family) => family switch {
        "ipv4" => "net.inet.ip.forwarding", "ipv6" => "net.inet6.ip6.forwarding",
        _ => throw new InvalidDataException("Unknown forwarding family")
    };
    private static bool ReadKernelFlag(string family) {
        string name = KernelName(family);
        var result = ToolProcess.Run(new System.Diagnostics.ProcessStartInfo("/usr/sbin/sysctl", "-n " + name), 3000);
        ToolProcess.RequireSuccess(result, "sysctl read " + name);
        return result.Output.Trim() switch { "0" => false, "1" => true,
            _ => throw new IOException("Invalid sysctl flag: " + name) };
    }
    private static void WriteKernelFlag(string family, bool enabled) => ToolProcess.RequireSuccess(
        ToolProcess.Run(new System.Diagnostics.ProcessStartInfo("/usr/sbin/sysctl", "-w " + KernelName(family) + (enabled ? "=1" : "=0")), 3000),
        "sysctl forwarding write");
}
