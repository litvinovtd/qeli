using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Qeli.Shared.Vpn;

namespace Qeli.Shared.Model;

public class DesktopServiceStatus
{
    public string Status { get; set; } = "Disconnected";
    public string? Extra { get; set; }
    public DateTime Time { get; set; }
    // Optional for older services. Windows GetTickCount64 milliseconds, including
    // suspend time; the GUI must use the same clock when checking snapshot age.
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public long? MonotonicTimeMs { get; set; }
    public long BytesUp { get; set; }
    public long BytesDown { get; set; }
    public DateTime? Since { get; set; }
    public DesktopTunnelAddresses Addresses { get; set; } = DesktopTunnelAddresses.Empty;
    public static T Decode<T>(byte[] bytes) where T : DesktopServiceStatus
    {
        var snapshot = JsonSerializer.Deserialize<T>(new UTF8Encoding(false, true).GetString(bytes))
            ?? throw new InvalidDataException("Service status is empty");
        Validate(snapshot);
        return snapshot;
    }
    public static void Validate(DesktopServiceStatus snapshot)
    {
        if (!Enum.TryParse<VpnStatus>(snapshot.Status, out var status) || !Enum.IsDefined(status)
            || snapshot.Status != status.ToString() || snapshot.Time == default
            || snapshot.BytesUp < 0 || snapshot.BytesDown < 0 || snapshot.Extra?.Length > 2048
            || snapshot.MonotonicTimeMs is < 0
            || snapshot.Addresses is null || !snapshot.Addresses.IsValid)
            throw new InvalidDataException("Invalid service status snapshot");
    }
    public static bool Fresh(DesktopServiceStatus snapshot, DateTime now, TimeSpan maximumAge,
        long? nowMonotonicMs = null)
    {
        if (snapshot.MonotonicTimeMs is long sampledAt)
        {
            // A bad/future monotonic timestamp must not be rescued by a fresh wall
            // timestamp. Only a missing optional field enables the legacy clock.
            return sampledAt >= 0 && nowMonotonicMs is long current && current >= sampledAt
                && current - sampledAt <= maximumAge.TotalMilliseconds;
        }
        var age = now.ToUniversalTime() - snapshot.Time.ToUniversalTime();
        return age <= maximumAge && age >= TimeSpan.FromSeconds(-5);
    }
}
