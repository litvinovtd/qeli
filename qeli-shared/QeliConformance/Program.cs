using System.Security.Cryptography;
using System.Text;
using Qeli.Shared.Crypto;
using Qeli.Shared.Model;
using Qeli.Shared.Protocol;
using Qeli.Shared.Vpn;

namespace Qeli.Conformance;

public static class Program
{
    public static int Main(string[] args)
    {
        string verb = args.FirstOrDefault()?.ToLowerInvariant() ?? "selftest";
        string[] rest = args.Skip(1).ToArray();
        return verb switch
        {
            "selftest" => SelfTest(),
            "packetbench" => PacketCodecBenchmark.Run("csharp-conformance", rest),
            _ => Usage(),
        };
    }

    private static int Usage()
    {
        Console.WriteLine("Usage: QeliConformance [selftest | packetbench [--ci]]");
        return 2;
    }

    private static int SelfTest()
    {
        int failed = 0;
        void Check(string name, bool ok)
        {
            Console.WriteLine($"  [{(ok ? "PASS" : "FAIL")}] {name}");
            if (!ok) failed++;
        }

        Console.WriteLine("qeli managed conformance self-test");

        var exchange = new KeyExchange();
        var alice = exchange.GenerateKeyPair();
        var bob = exchange.GenerateKeyPair();
        var ab = exchange.ComputeSharedSecret(alice.PrivateKey, bob.PublicKeyBytes);
        var ba = exchange.ComputeSharedSecret(bob.PrivateKey, alice.PublicKeyBytes);
        Check("X25519 shared secret symmetric", ab.SequenceEqual(ba) && ab.Length == 32);

        var (s2c, c2s) = KeyDerivation.DeriveKeys(ab);
        var salt = Encoding.UTF8.GetBytes("qeli-key-derivation-v1");
        var prk = HKDF.Extract(HashAlgorithmName.SHA256, ab, salt);
        var referenceC2s = HKDF.Expand(HashAlgorithmName.SHA256, prk, 32,
            Encoding.UTF8.GetBytes("client-to-server-enc-key"));
        var referenceS2c = HKDF.Expand(HashAlgorithmName.SHA256, prk, 32,
            Encoding.UTF8.GetBytes("server-to-client-enc-key"));
        Check("HKDF classic schedule matches RFC 5869 reference",
            c2s.SequenceEqual(referenceC2s) && s2c.SequenceEqual(referenceS2c));

        var x25519 = Enumerable.Range(0, 32).Select(i => (byte)i).ToArray();
        var mlkem = Enumerable.Range(0, 32).Select(i => (byte)(0xA0 + i)).ToArray();
        var (hybridS2c, hybridC2s) = KeyDerivation.DeriveKeysHybrid(x25519, mlkem);
        var hybridIkm = x25519.Concat(mlkem).ToArray();
        var hybridPrk = HKDF.Extract(HashAlgorithmName.SHA256, hybridIkm,
            Encoding.UTF8.GetBytes("qeli-key-derivation-v2-hybrid"));
        var hybridReferenceS2c = HKDF.Expand(HashAlgorithmName.SHA256, hybridPrk, 32,
            Encoding.UTF8.GetBytes("server-to-client-enc-key"));
        var hybridReferenceC2s = HKDF.Expand(HashAlgorithmName.SHA256, hybridPrk, 32,
            Encoding.UTF8.GetBytes("client-to-server-enc-key"));
        Check("HKDF hybrid schedule mixes ML-KEM and matches reference",
            hybridS2c.SequenceEqual(hybridReferenceS2c)
            && hybridC2s.SequenceEqual(hybridReferenceC2s)
            && !hybridS2c.SequenceEqual(KeyDerivation.DeriveKeys(x25519).serverToClient));

        var cipher = new PacketCipher(c2s);
        var nonce = RandomNumberGenerator.GetBytes(12);
        var message = Encoding.UTF8.GetBytes("the quick brown fox");
        var ciphertext = cipher.Encrypt(message, nonce);
        Check("ChaCha20-Poly1305 round-trip",
            cipher.Decrypt(ciphertext, nonce).SequenceEqual(message)
            && ciphertext.Length == message.Length + 16);

        var encoder = new PacketCodec(new PacketCipher(c2s),
            paddingEnabled: true, paddingMin: 10, paddingMax: 40);
        var decoder = new PacketCodec(new PacketCipher(c2s));
        bool codecOk = true;
        for (int i = 0; i < 5; i++)
        {
            var payload = RandomNumberGenerator.GetBytes(100 + i);
            codecOk &= decoder.Decrypt(encoder.Encrypt(payload)).SequenceEqual(payload);
        }
        Check("PacketCodec encode/decode + replay counter", codecOk);
        Check("PacketCodec heartbeat", decoder.Decrypt(encoder.Encrypt([])).Length == 0);

        var rawEncoder = new PacketCodec(new PacketCipher(c2s), paddingEnabled: false, raw: true);
        var rawDecoder = new PacketCodec(new PacketCipher(c2s), raw: true);
        var rawPayload = RandomNumberGenerator.GetBytes(120);
        var rawRecord = rawEncoder.Encrypt(rawPayload);
        int rawHeader = rawRecord.Length - (12 + rawPayload.Length + 16 + 8 + 2);
        Check("PacketCodec raw framing",
            rawDecoder.Decrypt(rawRecord).SequenceEqual(rawPayload)
            && rawHeader == 2 && rawRecord[0] != 0x17);

        Check("ObfsStream XOR symmetric", TestObfs());
        Check("ObfsStream WebSocket F3 vector", ObfsStream.SelfTestWsFraming());
        LinkConformance.Run(Check);
        PrpNonceConformance.Run(Check);
        WireConformance.Run(Check);
        RoamingPathConformance.Run(Check);
        ManagementEventConformance.Run(Check);

        var routeLocalCaptures = RouteLocalPolicy.BuildCapturePrefixes(
            new[] { "192.168.1.27/24", "10.8.1.4/16", "203.0.113.4/24", "10.9.0.7/32" });
        Check("route_local overrides connected RFC1918 prefixes without replacing them",
            routeLocalCaptures.SequenceEqual(new[]
            {
                "10.8.0.0/17", "10.8.128.0/17",
                "192.168.1.0/25", "192.168.1.128/25",
            }));
        Check("route_local capture respects broader and narrower exclusions",
            RouteLocalPolicy.BuildCapturePrefixes(
                new[] { "192.168.1.27/24" },
                new[] { "192.168.1.0/25", "192.168.1.192/26" })
            .SequenceEqual(new[] { "192.168.1.128/25" }));

        var mlKemEk = Enumerable.Range(0, 1184)
            .Select(i => unchecked((byte)(17 + i * 31))).ToArray();
        var hello = TlsHandshake.BuildClientHelloPqNative(alice.PublicKeyBytes, mlKemEk,
            "www.microsoft.com", padToMin: 1200);
        Check("native fake-TLS ClientHello bridge",
            hello.Length >= 1200 && hello[0] == 0x16
            && hello.AsSpan().IndexOf(new byte[] { 0x11, 0xec, 0x04, 0xc0 }) >= 0);
        Check("production AUTH budget shares the wire-limit contract",
            VpnConfig.AuthCredentialBudget == TransportWireLimits.AuthCredentialBudget);

        Console.WriteLine(failed == 0 ? "ALL PASS" : $"{failed} FAILED");
        return failed == 0 ? 0 : 1;
    }

    private static bool TestObfs()
    {
        var key = ObfsStream.DeriveKey("secret-psk");
        byte[]? clientNonce = null, serverNonce = null;
        var client = ObfsStream.Connect(key, false,
            nonce => clientNonce = nonce,
            _ => { serverNonce = RandomNumberGenerator.GetBytes(12); return serverNonce; });
        var server = ObfsStream.Connect(key, false,
            nonce => serverNonce = nonce,
            _ => clientNonce!);
        var plaintext = Encoding.UTF8.GetBytes("obfuscated payload over the wire");
        var onWire = client.TransformWrite(plaintext);
        return server.TransformRead(onWire).SequenceEqual(plaintext)
            && !onWire.SequenceEqual(plaintext);
    }
}
