using System.Globalization;
using Qeli.Shared;

namespace QeliMac.Vpn;

/// <summary>macOS profile dev_node: absent/auto or a canonical utunN. No driver,
/// interface renaming, adoption of existing devices, or automatic fallback.</summary>
internal static class UtunSelection
{
    internal const int MaxNumber=65534; // Deliberately bounded client policy, not a kernel maximum.
    internal static int? Parse(string? name)
    {
        if(string.IsNullOrWhiteSpace(name) || name.Equals("auto",StringComparison.OrdinalIgnoreCase)) return null;
        if(name.StartsWith("utun",StringComparison.Ordinal) &&
            int.TryParse(name.AsSpan(4),NumberStyles.None,CultureInfo.InvariantCulture,out int number)
            && number is >=0 and <=MaxNumber && name=="utun"+number.ToString(CultureInfo.InvariantCulture)) return number;
        throw new InvalidDataException(Loc.T("MacUtunInvalid"));
    }
    internal static string FromEditor(string? text)
    {
        string value=(text ?? "").Trim();
        if(value.Length==0 || value.Equals("auto",StringComparison.OrdinalIgnoreCase)) return "auto";
        if(value.All(char.IsAsciiDigit)) value="utun"+value;
        _=Parse(value);return value;
    }
    internal static uint ControlUnit(int? number)
    {
        if(number is null) return 0;
        if(number is <0 or >MaxNumber) throw new InvalidDataException(Loc.T("MacUtunInvalid"));
        return checked((uint)number.Value+1); // Darwin sc_unit 1 creates utun0; 0 requests auto.
    }
    internal static IOException ConnectError(int? number,int error) => new(number is {} n
        ? error is 16 or 48 // Darwin EBUSY / EADDRINUSE, not Windows errno values.
            ? Loc.F("MacUtunBusy",n,error)
            : Loc.F("MacUtunConnectFailed",n,error)
        : $"utun: connect failed (errno {error})");
}
