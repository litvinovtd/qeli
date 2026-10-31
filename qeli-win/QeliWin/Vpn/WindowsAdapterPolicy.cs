using System.IO;
using System.Text.Json;
using System.Text.Json.Nodes;
using Qeli.Shared.Model;

namespace QeliWin.Vpn;

/// <summary>App preference -> immutable connection/service snapshot. Never edits the
/// stored profile's flag or substitutes a profile's explicit dev_node in-place.</summary>
internal static class WindowsAdapterPolicy
{
    internal const string Off="off", Profiles="profiles", Global="global";
    internal static readonly Guid GlobalKey=new("f08e6061-c9d9-44d6-b9b6-4e49c0a6ade8");
    internal const string GlobalName="Qeli-Global";
    internal static string Validate(string? mode) => mode is Off or Profiles or Global ? mode
        : throw new InvalidDataException("Invalid persistent adapter mode; choose Off, Per profile or Global in Settings");
    internal static string ResolvedMode(VpnConfig config) => config.WindowsAdapterMode is null?Off:Validate(config.WindowsAdapterMode);
    internal static bool Persistent(VpnConfig config) => ResolvedMode(config) switch {
        Global=>!config.UsesAppFilter,
        Profiles=>config.WindowsPersistentAdapter,
        _=>false,
    };
    internal static bool UsesGlobal(VpnConfig config) => ResolvedMode(config)==Global && Persistent(config);
    internal static void ValidateConnection(VpnConfig config)
    {
        _=ResolvedMode(config);
        if(Persistent(config) && config.UsesAppFilter)
            throw new InvalidOperationException("Profile-owned permanent Wintun cannot be combined with per-app WinDivert");
    }
    internal static VpnConfig Snapshot(VpnConfig profile,string mode)
    {
        Validate(mode);
        var copy=JsonSerializer.SerializeToNode(profile)!.AsObject();
        copy[nameof(VpnConfig.WindowsAdapterMode)]=mode;
        // Keep the original profile flag even in service snapshots. Materializing
        // Off/Global into that flag would lose the user's Per-profile preference
        // when a later mode change starts from the protected service snapshot.
        return copy.Deserialize<VpnConfig>()!; // JSON copy preserves Id; Clone() intentionally changes it.
    }

    /// <summary>Run only while the exclusive machine mode gate is held. Never clear an
    /// active/foreign lease, invent a new device, delete a receipt, or delete a device.</summary>
    internal static void RecoverIdlePlans(PersistentWintunDevice.IStore? store=null,
        PersistentWintunDevice.IPlatform? platform=null,
        Func<System.Diagnostics.ProcessStartInfo,string,string>? run=null)
    {
        store ??=PersistentWintunDevice.Store;platform ??=PersistentWintunDevice.Platform;
        run ??=VpnTunnel.RunPersistentCommand;
        foreach(var key in store.Keys().Order())
        {
            bool pending;
            using(var gate=store.Lock(key)) {
                var record=store.Read(key);
                if(record is null) continue;
                PersistentWintunDevice.Validate(record,key);
                pending=record.Network!=null;
            }
            if(!pending) continue;
            var lease=PersistentWintunDevice.OpenExisting(key,store,platform);
            try {PersistentWintunNetwork.Recover(lease,run);}
            finally {lease.CloseRecoveryHandle();}
        }
    }

    internal static void SaveMode(string? previous,string proposed,Action save,
        Func<IDisposable>? exclusive=null,Action? recover=null,Func<Action?>? stage=null,
        Func<string?>? readCurrent=null,Func<IDisposable>? shared=null,Action? requireIdle=null)
    {
        Validate(proposed);
        if(readCurrent!=null) {
            // An unrelated Settings Save must not overwrite a mode another GUI has
            // changed meanwhile. Read/save under a shared lease, or upgrade to a writer.
            using var reader=(shared ?? WindowsAdapterModeGate.Shared)();
            if(readCurrent()==proposed) {save();return;}
        }
        else if(previous==proposed) {save();return;}
        using var gate=(exclusive ?? WindowsAdapterModeGate.Exclusive)();
        if(readCurrent!=null && readCurrent()==proposed) {save();return;}
        requireIdle?.Invoke();
        (recover ?? (()=>RecoverIdlePlans()))();
        var rollback=stage?.Invoke(); // Stage the protected idle service snapshot under the same gate.
        try {save();} // Publish preferences ONLY after rollback and service staging succeeded.
        catch(Exception failure) {
            try {rollback?.Invoke();}
            catch(Exception undo) {throw new AggregateException("Settings publication and service-policy rollback failed; keep VPN stopped and retry Settings",failure,undo);}
            throw;
        }
    }
}
