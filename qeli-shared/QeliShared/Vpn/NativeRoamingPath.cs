using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Qeli.Shared.Vpn;

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed class NativePathFlags
{
    [JsonPropertyName("default_route_changed")]
    public bool DefaultRouteChanged { get; set; }

    [JsonPropertyName("wake")]
    public bool Wake { get; set; }

    [JsonPropertyName("same_network_nat_failure")]
    public bool SameNetworkNatFailure { get; set; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed class NativePathResolution
{
    [JsonPropertyName("address")]
    public string Address { get; set; } = "";

    [JsonPropertyName("ttl_secs")]
    public uint TtlSecs { get; set; }
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed class NativePathUpdate
{
    [JsonPropertyName("generation")]
    public ulong Generation { get; set; }

    [JsonPropertyName("update_id")]
    public ulong UpdateId { get; set; }

    [JsonPropertyName("platform_path_id")]
    public string PlatformPathId { get; set; } = "";

    [JsonPropertyName("reason")]
    public string Reason { get; set; } = "";

    [JsonPropertyName("network_token")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? NetworkToken { get; set; }

    [JsonPropertyName("interface_index")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public uint? InterfaceIndex { get; set; }

    [JsonPropertyName("local_addresses")]
    public List<string> LocalAddresses { get; set; } = new();

    [JsonPropertyName("resolved_addresses")]
    public List<NativePathResolution> ResolvedAddresses { get; set; } = new();

    [JsonPropertyName("flags")]
    public NativePathFlags Flags { get; set; } = new();
}

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed class NativePathCommand
{
    [JsonPropertyName("generation")]
    public ulong Generation { get; set; }

    [JsonPropertyName("candidate_id")]
    public ulong CandidateId { get; set; }

    [JsonPropertyName("action")]
    public string Action { get; set; } = "";

    [JsonPropertyName("path")]
    public NativePathUpdate Path { get; set; } = new();

    [JsonPropertyName("socket_fd")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public long? SocketHandle { get; set; }

    [JsonPropertyName("reason")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Reason { get; set; }
}

/// <summary>Strict managed view of the ABI 1.12/1.13 roaming JSON contract.</summary>
internal static class NativeRoamingPath
{
    private const int MaxPayloadBytes = 64 * 1024;
    private const int MaxAddresses = 16;
    private const uint MaxTtlSecs = 7 * 24 * 60 * 60;
    private static readonly HashSet<string> Actions = new(StringComparer.Ordinal)
    {
        "prepare_path", "bind_socket", "commit_path", "abort_path",
    };
    private static readonly HashSet<string> Reasons = new(StringComparer.Ordinal)
    {
        "network_changed", "default_route_changed", "wake",
        "same_network_nat_failure", "manual_probe",
    };

    internal static NativePathCommand DecodeCommand(NativeTransportCore.NativeEvent request)
    {
        if (request.Kind != NativeTransportCore.EventPathCommand
            || request.PayloadFormat != NativeTransportCore.PayloadJson
            || request.Sequence == 0 || request.PlanGeneration == 0 || request.ErrorCode != 0)
            throw new InvalidDataException("invalid native path-command event envelope");
        if (string.IsNullOrEmpty(request.Payload))
            throw new InvalidDataException("native path-command payload is empty");
        if (Encoding.UTF8.GetByteCount(request.Payload) > MaxPayloadBytes)
            throw new InvalidDataException("native path-command payload exceeds 64 KiB");
        NativePathCommand command;
        try
        {
            using JsonDocument document = JsonDocument.Parse(request.Payload,
                new JsonDocumentOptions { MaxDepth = 16 });
            RejectDuplicateFields(document.RootElement);
            command = document.RootElement.Deserialize<NativePathCommand>()
                ?? throw new InvalidDataException("native path-command payload is empty");
        }
        catch (JsonException error)
        {
            throw new InvalidDataException("native path-command payload is invalid", error);
        }
        if (command.Generation != request.PlanGeneration || command.CandidateId == 0)
            throw new InvalidDataException("native path-command correlation mismatch");
        if (!Actions.Contains(command.Action))
            throw new InvalidDataException($"unsupported native path action '{command.Action}'");
        if ((command.Action == "bind_socket") != command.SocketHandle.HasValue
            || command.SocketHandle is < 0)
            throw new InvalidDataException("only BIND_SOCKET may carry a non-negative socket handle");
        if (command.Path is null)
            throw new InvalidDataException("native path-command has no path object");
        if (command.Path.Generation != command.Generation)
            throw new InvalidDataException("native path-command embeds another generation");
        ValidateUpdate(command.Path);
        return command;
    }

    internal static ulong DecodeRefreshGeneration(NativeTransportCore.NativeEvent request)
    {
        if (request.Kind != NativeTransportCore.EventPathRefresh
            || request.PayloadFormat != NativeTransportCore.PayloadNone
            || request.Sequence == 0 || request.PlanGeneration == 0 || request.ErrorCode != 0
            || !string.IsNullOrEmpty(request.Payload))
            throw new InvalidDataException("invalid native path-refresh event");
        return request.PlanGeneration;
    }

    internal static string EncodeUpdate(NativePathUpdate? update)
    {
        ValidateUpdate(update);
        return JsonSerializer.Serialize(update);
    }

    internal static void ValidateUpdate(NativePathUpdate? update)
    {
        if (update is null)
            throw new InvalidDataException("path update is missing");
        if (update.Generation == 0 || update.UpdateId == 0)
            throw new InvalidDataException("path generation and update id must be non-zero");
        ValidateIdentifier("platform path id", update.PlatformPathId);
        if (update.NetworkToken != null)
            ValidateIdentifier("network token", update.NetworkToken);
        if (update.NetworkToken == null && update.InterfaceIndex == null)
            throw new InvalidDataException("path update requires a network token or interface index");
        if (update.InterfaceIndex == 0)
            throw new InvalidDataException("path interface index must be non-zero");
        if (!Reasons.Contains(update.Reason))
            throw new InvalidDataException($"unsupported path-update reason '{update.Reason}'");
        if (update.Flags is null || update.LocalAddresses is null
            || update.ResolvedAddresses is null)
            throw new InvalidDataException("path update contains a null collection or flags object");
        bool matchingFlag = update.Reason switch
        {
            "default_route_changed" => update.Flags.DefaultRouteChanged,
            "wake" => update.Flags.Wake,
            "same_network_nat_failure" => update.Flags.SameNetworkNatFailure,
            _ => true,
        };
        if (!matchingFlag)
            throw new InvalidDataException("path-update reason is missing its matching flag");
        if (update.LocalAddresses.Count is < 1 or > MaxAddresses
            || update.ResolvedAddresses.Count is < 1 or > MaxAddresses)
            throw new InvalidDataException("path update requires 1..16 local and resolved addresses");

        var local = new HashSet<IPAddress>();
        var families = new HashSet<AddressFamily>();
        foreach (string text in update.LocalAddresses)
        {
            if (text is null)
                throw new InvalidDataException("path update contains a null local address");
            IPAddress address = ParseUsableAddress("local path", text);
            if (!local.Add(address))
                throw new InvalidDataException($"duplicate local path address '{text}'");
            families.Add(address.AddressFamily);
        }
        var resolved = new HashSet<IPAddress>();
        bool compatible = false;
        foreach (NativePathResolution item in update.ResolvedAddresses)
        {
            if (item is null)
                throw new InvalidDataException("path update contains a null resolution");
            IPAddress address = ParseUsableAddress("resolved path", item.Address);
            if (!resolved.Add(address))
                throw new InvalidDataException($"duplicate resolved path address '{item.Address}'");
            if (item.TtlSecs > MaxTtlSecs)
                throw new InvalidDataException("resolved path TTL exceeds seven days");
            compatible |= families.Contains(address.AddressFamily);
        }
        if (!compatible)
            throw new InvalidDataException("path update has no family-compatible resolved address");
    }

    private static void RejectDuplicateFields(JsonElement element)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (JsonProperty property in element.EnumerateObject())
            {
                if (!names.Add(property.Name))
                    throw new InvalidDataException(
                        $"native path-command contains duplicate field '{property.Name}'");
                RejectDuplicateFields(property.Value);
            }
        }
        else if (element.ValueKind == JsonValueKind.Array)
        {
            foreach (JsonElement item in element.EnumerateArray())
                RejectDuplicateFields(item);
        }
    }

    private static void ValidateIdentifier(string label, string? value)
    {
        if (value is null)
            throw new InvalidDataException($"{label} is missing");
        int bytes = Encoding.UTF8.GetByteCount(value);
        if (bytes is < 1 or > 256 || value.Any(char.IsControl))
            throw new InvalidDataException($"{label} must be 1..256 UTF-8 bytes without controls");
    }

    private static IPAddress ParseUsableAddress(string label, string? text)
    {
        if (!IPAddress.TryParse(text, out IPAddress? address)
            || address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any)
            || IPAddress.IsLoopback(address)
            || address.IsIPv6Multicast
            || address.Equals(IPAddress.Broadcast)
            || (address.AddressFamily == AddressFamily.InterNetworkV6 && address.ScopeId != 0))
            throw new InvalidDataException($"invalid {label} address '{text}'");
        return address;
    }
}
