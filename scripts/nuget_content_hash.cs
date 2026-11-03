using NuGet.Packaging;
using System.Security.Cryptography;
using System.Text.Json;
foreach (var path in File.ReadAllLines(args[0]))
{
    using var reader = new PackageArchiveReader(path);
    var signed = await reader.IsSignedAsync(CancellationToken.None);
    if (signed)
    {
        var signature = await reader.GetPrimarySignatureAsync(CancellationToken.None) ?? throw new InvalidDataException("Missing primary signature");
        signature.SignedCms.CheckSignature(verifySignatureOnly: true);
        await reader.ValidateIntegrityAsync(signature.SignatureContent, CancellationToken.None);
    }
    using var stream = File.OpenRead(path);
    Console.WriteLine(JsonSerializer.Serialize(new { path, signed, contentHash = reader.GetContentHash(CancellationToken.None), archiveSha256 = Convert.ToHexStringLower(SHA256.HashData(stream)) }));
}
