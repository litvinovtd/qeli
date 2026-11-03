using System.Buffers.Binary;
using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;
using System.Text.Json;

// Inspect metadata, never load/execute the candidate assembly or its initializers.
if (args.Length != 1) return 2;
using var input = File.OpenRead(args[0]);
using var pe = new PEReader(input);
var metadata = pe.GetMetadataReader();
var address = pe.PEHeaders.CorHeader?.ResourcesDirectory.RelativeVirtualAddress ?? throw new InvalidDataException("No CLR resource directory");
var data = pe.GetSectionData(address).GetContent();
var output = new SortedDictionary<string, string>(StringComparer.Ordinal);
foreach (var handle in metadata.ManifestResources)
{
    var resource = metadata.GetManifestResource(handle);
    var name = metadata.GetString(resource.Name);
    if (!name.StartsWith("Qeli.Legal/", StringComparison.Ordinal)) continue;
    if (!resource.Implementation.IsNil) throw new InvalidDataException("External legal resource");
    var offset = checked((int)resource.Offset);
    if (offset < 0 || offset > data.Length - 4) throw new InvalidDataException("Invalid resource offset");
    var size = BinaryPrimitives.ReadInt32LittleEndian(data.AsSpan(offset, 4));
    if (size < 0 || size > 16 * 1024 * 1024 || size > data.Length - offset - 4) throw new InvalidDataException("Invalid resource size");
    name = name["Qeli.Legal/".Length..].Replace('\\', '/');
    if (!output.TryAdd(name, Convert.ToBase64String(data.AsSpan(offset + 4, size)))) throw new InvalidDataException("Duplicate legal resource");
}
if (output.Count == 0) throw new InvalidDataException("Missing embedded legal resources");
Console.WriteLine(JsonSerializer.Serialize(output));
return 0;
