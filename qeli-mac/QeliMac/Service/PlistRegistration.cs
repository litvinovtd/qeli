using System.Text;
using System.Xml;
using System.Xml.Linq;

namespace QeliMac.Service;

internal static class PlistRegistration
{
    internal static string Escape(string text) => System.Security.SecurityElement.Escape(text)!;
    internal static void Validate(byte[] bytes, string label, string executable)
    {
        if (bytes.Length > 1024 * 1024) throw new InvalidDataException("Daemon plist exceeds 1 MiB");
        using var input = new MemoryStream(bytes);
        using var reader = XmlReader.Create(input, new XmlReaderSettings
        { DtdProcessing = DtdProcessing.Ignore, XmlResolver = null, MaxCharactersInDocument = 1024 * 1024 });
        var root = XDocument.Load(reader).Root;
        if (root?.Name != "plist" || root.Elements().Count() != 1 || root.Element("dict") is not { } dict)
            throw new InvalidDataException("Daemon plist must contain one dictionary");
        var entries = dict.Elements().ToArray();
        var values = new Dictionary<string, XElement>(StringComparer.Ordinal);
        for (int i = 0; i < entries.Length; i += 2)
        {
            if (i + 1 == entries.Length || entries[i].Name != "key" || !values.TryAdd(entries[i].Value, entries[i + 1]))
                throw new InvalidDataException("Daemon plist has invalid or duplicate keys");
        }
        string Required(string key)
        {
            if (!values.TryGetValue(key, out var value) || value.Name != "string")
                throw new InvalidDataException($"Daemon plist has invalid {key}");
            return value.Value;
        }
        if (Required("Label") != label || !values.TryGetValue("ProgramArguments", out var args)
            || args.Name != "array" || args.Elements().Any(e => e.Name != "string")
            || !args.Elements().Select(e => e.Value).SequenceEqual(new[] { executable, "--service" }))
            throw new InvalidDataException("Daemon plist does not launch this Qeli service");
        if (values.TryGetValue("Program", out var program) && (program.Name != "string" || program.Value != executable))
            throw new InvalidDataException("Daemon plist overrides the Qeli executable");
        if (values.TryGetValue("UserName", out var user) && (user.Name != "string" || user.Value != "root"))
            throw new InvalidDataException("Daemon plist changes the root account");
        if (values.TryGetValue("GroupName", out var group) && (group.Name != "string" || group.Value != "wheel"))
            throw new InvalidDataException("Daemon plist changes the root group");
        foreach (var key in new[] { "RunAtLoad", "KeepAlive" })
            if (!values.TryGetValue(key, out var flag) || flag.Name != "true")
                throw new InvalidDataException($"Daemon plist changes {key}");
        var allowed = new HashSet<string>(new[] { "Label", "ProgramArguments", "Program", "UserName", "GroupName",
            "RunAtLoad", "KeepAlive", "ThrottleInterval", "StandardErrorPath" }, StringComparer.Ordinal);
        if (values.Keys.Any(key => !allowed.Contains(key)))
            throw new InvalidDataException("Daemon plist contains unsupported execution overrides");
        if (values.TryGetValue("StandardErrorPath", out var stderr)
            && (stderr.Name != "string" || stderr.Value != "/Library/Application Support/Qeli/daemon.stderr.log"))
            throw new InvalidDataException("Daemon plist redirects privileged stderr outside Qeli");
    }
}
