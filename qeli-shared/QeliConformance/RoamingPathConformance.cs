using System.Text.Json;
using Qeli.Shared.Vpn;

namespace Qeli.Shared.Protocol;

internal static class RoamingPathConformance
{
    internal static void Run(Action<string, bool> check)
    {
        static NativePathUpdate ValidUpdate() => new()
        {
            Generation = 7,
            UpdateId = 3,
            PlatformPathId = "windows-if-12",
            Reason = "network_changed",
            NetworkToken = "windows-luid-42",
            InterfaceIndex = 12,
            LocalAddresses = new List<string> { "192.0.2.8", "2001:db8::8" },
            ResolvedAddresses = new List<NativePathResolution>
            {
                new() { Address = "198.51.100.7", TtlSecs = 30 },
                new() { Address = "2001:db8::7", TtlSecs = 30 },
            },
        };

        var update = ValidUpdate();
        string encodedUpdate = NativeRoamingPath.EncodeUpdate(update);
        check("roaming-path: managed update preserves dual-stack path facts",
            encodedUpdate.Contains("windows-luid-42", StringComparison.Ordinal)
            && encodedUpdate.Contains("2001:db8::7", StringComparison.Ordinal));

        long wideSocket = (long)int.MaxValue + 42;
        string payload = JsonSerializer.Serialize(new NativePathCommand
        {
            Generation = 7,
            CandidateId = 91,
            Action = "bind_socket",
            Path = update,
            SocketHandle = wideSocket,
        });
        var request = new NativeTransportCore.NativeEvent(
            NativeTransportCore.EventPathCommand,
            NativeTransportCore.StateRunning,
            NativeTransportCore.PayloadJson,
            55,
            7,
            0,
            payload);
        NativePathCommand decoded = NativeRoamingPath.DecodeCommand(request);
        check("roaming-path: Windows SOCKET survives the signed 64-bit ABI",
            decoded.SocketHandle == wideSocket && decoded.CandidateId == 91);

        bool correlationRejected;
        try
        {
            NativeRoamingPath.DecodeCommand(request with { PlanGeneration = 8 });
            correlationRejected = false;
        }
        catch (InvalidDataException) { correlationRejected = true; }
        check("roaming-path: mismatched generation is rejected", correlationRejected);

        bool unknownRejected;
        try
        {
            string unknown = payload[..^1] + ",\"unexpected\":true}";
            NativeRoamingPath.DecodeCommand(request with { Payload = unknown });
            unknownRejected = false;
        }
        catch (InvalidDataException) { unknownRejected = true; }
        check("roaming-path: unknown command fields are rejected", unknownRejected);

        bool duplicateRejected;
        try
        {
            string duplicate = payload[..^1] + ",\"candidate_id\":92}";
            NativeRoamingPath.DecodeCommand(request with { Payload = duplicate });
            duplicateRejected = false;
        }
        catch (InvalidDataException) { duplicateRejected = true; }
        check("roaming-path: duplicate command fields are rejected", duplicateRejected);

        bool nullPathRejected;
        try
        {
            string nullPath = payload.Replace($"\"path\":{JsonSerializer.Serialize(update)}",
                "\"path\":null", StringComparison.Ordinal);
            NativeRoamingPath.DecodeCommand(request with { Payload = nullPath });
            nullPathRejected = false;
        }
        catch (InvalidDataException) { nullPathRejected = true; }
        check("roaming-path: null nested objects are rejected", nullPathRejected);

        bool partialCapabilityRejected;
        try
        {
            NativeTransportCore.New("", false, false, roamingCapabilities:
                NativeTransportCore.PlatformPathTransactions);
            partialCapabilityRejected = false;
        }
        catch (ArgumentException) { partialCapabilityRejected = true; }
        check("roaming-path: partial platform capability is rejected before native use",
            partialCapabilityRejected);

        bool invalidAckRejected;
        try
        {
            NativeTransportCore.PathCommandResult(0, request with { Sequence = 0 }, decoded,
                NativeTransportCore.PathCommandOutcome.Rejected);
            invalidAckRejected = false;
        }
        catch (InvalidDataException) { invalidAckRejected = true; }
        check("roaming-path: invalid acknowledgement envelope is rejected", invalidAckRejected);
        check("roaming-path: ABI 1.14 preserves rollback-safe and state-unknown outcomes",
            (int)NativeTransportCore.PathCommandOutcome.Accepted == 0
            && (int)NativeTransportCore.PathCommandOutcome.Rejected == 1
            && (int)NativeTransportCore.PathCommandOutcome.PlatformStateUnknown == 2
            && VpnTunnelBase.PathCommandOutcomeForError(new InvalidOperationException())
                == NativeTransportCore.PathCommandOutcome.Rejected
            && VpnTunnelBase.PathCommandOutcomeForError(
                new NativeRoamingPlatformStateUnknownException("unsafe", new IOException()))
                == NativeTransportCore.PathCommandOutcome.PlatformStateUnknown);

        bool incompatibleRejected;
        try
        {
            var incompatible = ValidUpdate();
            incompatible.LocalAddresses = new List<string> { "192.0.2.8" };
            incompatible.ResolvedAddresses = new List<NativePathResolution>
            {
                new() { Address = "2001:db8::7", TtlSecs = 30 },
            };
            NativeRoamingPath.EncodeUpdate(incompatible);
            incompatibleRejected = false;
        }
        catch (InvalidDataException) { incompatibleRejected = true; }
        check("roaming-path: incompatible source/remote families are rejected", incompatibleRejected);

        var refresh = new NativeTransportCore.NativeEvent(
            NativeTransportCore.EventPathRefresh,
            NativeTransportCore.StateRunning,
            NativeTransportCore.PayloadNone,
            56,
            7,
            0,
            "");
        check("roaming-path: no-payload refresh keeps its generation",
            NativeRoamingPath.DecodeRefreshGeneration(refresh) == 7);
    }
}
