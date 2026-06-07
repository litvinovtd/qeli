using System.IO;
using System.Security.Cryptography;
using System.Text;
using QeliMac.Crypto;
using QeliMac.Model;
using QeliMac.Protocol;
using QeliMac.Vpn;

namespace QeliMac;

/// <summary>
/// Headless command-line modes for testing without the GUI:
///   QeliMac selftest                       — crypto/codec/parse round-trips (no network, no root)
///   QeliMac handshake &lt;link|json|file&gt;     — connect + full handshake only (no root)
///   QeliMac connect   &lt;link|json|file&gt; [s]  — full tunnel (needs root)
///   QeliMac genassets &lt;dir&gt;                — render the brand PNGs into a directory
/// </summary>
public static class CliRunner
{
    public static int Run(string verb, string[] rest)
    {
        return verb.ToLowerInvariant() switch
        {
            "selftest" => SelfTest(),
            "handshake" => Handshake(rest),
            "connect" => Connect(rest),
            "genassets" => GenAssets(rest),
            "genicns" => GenIcns(rest),
            _ => Usage(),
        };
    }

    private static int Usage()
    {
        Console.WriteLine("Usage: QeliMac [selftest | handshake <link|json|file> | connect <link|json|file> [seconds] | genassets <dir> | genicns <out.icns>]");
        return 2;
    }

    // ── crypto self-test ────────────────────────────────────────────────────────
    private static int SelfTest()
    {
        int failed = 0;
        void Check(string name, bool ok) { Console.WriteLine($"  [{(ok ? "PASS" : "FAIL")}] {name}"); if (!ok) failed++; }

        Console.WriteLine("qeli-mac self-test");

        // X25519 agreement is symmetric.
        var ke = new KeyExchange();
        var a = ke.GenerateKeyPair();
        var b = ke.GenerateKeyPair();
        var ab = ke.ComputeSharedSecret(a.PrivateKey, b.PublicKeyBytes);
        var ba = ke.ComputeSharedSecret(b.PrivateKey, a.PublicKeyBytes);
        Check("X25519 shared secret symmetric", ab.SequenceEqual(ba) && ab.Length == 32);

        // Hand-rolled HKDF matches System.Security.Cryptography.HKDF.
        var shared = ab;
        var (s2c, c2s) = KeyDerivation.DeriveKeys(shared);
        var salt = Encoding.UTF8.GetBytes("qeli-key-derivation-v1");
        var prk = HKDF.Extract(HashAlgorithmName.SHA256, shared, salt);
        var refC2s = HKDF.Expand(HashAlgorithmName.SHA256, prk, 32, Encoding.UTF8.GetBytes("client-to-server-enc-key"));
        var refS2c = HKDF.Expand(HashAlgorithmName.SHA256, prk, 32, Encoding.UTF8.GetBytes("server-to-client-enc-key"));
        Check("HKDF DeriveKeys matches RFC 5869 reference", c2s.SequenceEqual(refC2s) && s2c.SequenceEqual(refS2c));

        // ChaCha20-Poly1305 AEAD round-trip.
        var cipher = new PacketCipher(c2s);
        var nonce = RandomNumberGenerator.GetBytes(12);
        var msg = Encoding.UTF8.GetBytes("the quick brown fox");
        var ct = cipher.Encrypt(msg, nonce);
        Check("ChaCha20-Poly1305 round-trip", cipher.Decrypt(ct, nonce).SequenceEqual(msg) && ct.Length == msg.Length + 16);

        // PacketCodec record encode/decode (two codecs sharing the same key).
        var enc = new PacketCodec(new PacketCipher(c2s), paddingEnabled: true, paddingMin: 10, paddingMax: 40);
        var dec = new PacketCodec(new PacketCipher(c2s));
        bool codecOk = true;
        for (int i = 0; i < 5; i++)
        {
            var payload = RandomNumberGenerator.GetBytes(100 + i);
            var rec = enc.Encrypt(payload);
            codecOk &= dec.Decrypt(rec).SequenceEqual(payload);
        }
        Check("PacketCodec encode/decode + counter/replay", codecOk);

        // Empty payload (heartbeat) survives the codec.
        var hbRec = enc.Encrypt(Array.Empty<byte>());
        Check("PacketCodec heartbeat (empty payload)", dec.Decrypt(hbRec).Length == 0);

        // `plain` wire mode: bare length-prefixed records (no TLS header). Round-trips
        // and emits a 2-byte (not 5-byte) header.
        var rawEnc = new PacketCodec(new PacketCipher(c2s), paddingEnabled: false, raw: true);
        var rawDec = new PacketCodec(new PacketCipher(c2s), raw: true);
        var rawPayload = RandomNumberGenerator.GetBytes(120);
        var rawRec = rawEnc.Encrypt(rawPayload);
        int rawHdr = rawRec.Length - (12 + rawPayload.Length + 16 + 8 + 2); // record - (nonce+ct)
        Check("PacketCodec raw framing (plain mode)",
            rawDec.Decrypt(rawRec).SequenceEqual(rawPayload) && rawHdr == 2 && rawRec[0] != 0x17);

        // ObfsStream keystream is symmetric across a crossed in-memory pipe.
        Check("ObfsStream XOR symmetric", TestObfs());

        // qeli:// link parses to the expected fields (a prod link shape).
        var link = "qeli://client1:dLYkV5x6JKBFr6@222.167.246.143:443?proto=tcp&mode=fake-tls" +
                   "&key=7ff1c27410a4f36f5306554a9ff3bd486c2692f4e40ed57c78c18c90638b2057&sni=www.microsoft.com#Client%201";
        var cfg = VpnConfig.FromQeliUri(link);
        Check("qeli:// parse",
            cfg.ServerAddress == "222.167.246.143" && cfg.Port == 443 && cfg.Username == "client1" &&
            cfg.Password == "dLYkV5x6JKBFr6" && cfg.Sni == "www.microsoft.com" &&
            cfg.ServerPublicKeyHex == "7ff1c27410a4f36f5306554a9ff3bd486c2692f4e40ed57c78c18c90638b2057" &&
            cfg.Name == "Client 1");

        // Flat-INI client config parses to the expected fields.
        var ini = "[qeli]\nserver = 222.167.246.143:443\nproto = tcp\nuser = client1\n" +
                  "pass = secret\nmode = obfs\nobfs_key = psk123\nsni = www.apple.com\nroute_local = true\n" +
                  "[logging]\nlevel = info\n";
        var ic = VpnConfig.FromIni(ini);
        Check("INI parse",
            ic.ServerAddress == "222.167.246.143" && ic.Port == 443 && ic.Protocol == "tcp" &&
            ic.Username == "client1" && ic.Password == "secret" && ic.WireMode == "obfs" &&
            ic.ObfsKey == "psk123" && ic.Sni == "www.apple.com" && ic.RouteLocalNetworks &&
            ic.ObfsFronting == "websocket");

        // reality-tls INI (mode + key + reality_sid) parses, matching server-reality.conf.
        var rini = "[qeli]\nserver = host:443\nproto = tcp\nuser = u\npass = p\n" +
                   "key = 7ff1c27410a4f36f5306554a9ff3bd486c2692f4e40ed57c78c18c90638b2057\n" +
                   "mode = reality-tls\nreality_sid = 0123456789abcdef\nsni = www.microsoft.com\n";
        var rc = VpnConfig.FromIni(rini);
        Check("reality-tls INI parse",
            rc.WireMode == "reality-tls" && rc.RealityShortId == "0123456789abcdef" &&
            rc.ServerPublicKeyHex == "7ff1c27410a4f36f5306554a9ff3bd486c2692f4e40ed57c78c18c90638b2057");

        // ToIni → FromIni round-trip preserves the new wire-mode fields (front + reality_sid + quic).
        var obfsRt = new VpnConfig { WireMode = "obfs", ObfsKey = "k", ObfsFronting = "none",
            Protocol = "udp", QuicEnabled = true, ServerAddress = "h", Port = 8448 };
        var obfsBack = VpnConfig.FromIni(obfsRt.ToIni());
        var realRt = new VpnConfig { WireMode = "reality-tls", RealityShortId = "abcdef01",
            ServerAddress = "h", Port = 443 };
        var realBack = VpnConfig.FromIni(realRt.ToIni());
        Check("INI round-trip (front/quic/reality_sid)",
            obfsBack.ObfsFronting == "none" && obfsBack.QuicEnabled &&
            realBack.RealityShortId == "abcdef01" && realBack.WireMode == "reality-tls");

        // ClientHello builds and pads to the UDP minimum.
        var hello = TlsHandshake.BuildClientHello(a.PublicKeyBytes, "www.microsoft.com", padToMin: 1200);
        Check("ClientHello builds + UDP padding (>=1200B, type 0x16)", hello.Length >= 1200 && hello[0] == 0x16);

        // Brand renderer produces a PNG (SkiaSharp path).
        bool brandOk; try { brandOk = Branding.AppIconPng(64).Length > 0; } catch { brandOk = false; }
        Check("Branding renders app icon PNG (SkiaSharp)", brandOk);

        Console.WriteLine(failed == 0 ? "ALL PASS" : $"{failed} FAILED");
        return failed == 0 ? 0 : 1;
    }

    private static bool TestObfs()
    {
        var key = ObfsStream.DeriveKey("secret-psk");
        byte[]? clientNonce = null, serverNonce = null;
        var client = ObfsStream.Connect(key, false, n => clientNonce = n, _ => { serverNonce = RandomNumberGenerator.GetBytes(12); return serverNonce; });
        var server = ObfsStream.Connect(key, false, n => serverNonce = n, _ => clientNonce!);
        var plain = Encoding.UTF8.GetBytes("obfuscated payload over the wire");
        var onWire = client.TransformWrite(plain);
        var recovered = server.TransformRead(onWire);
        return recovered.SequenceEqual(plain) && !onWire.SequenceEqual(plain);
    }

    // ── live handshake / connect ──────────────────────────────────────────────────
    // Accepts a file path OR an inline config, in any format: flat-INI (current),
    // a qeli:// link, or legacy JSON. (VpnConfig.Parse detects by content.)
    private static VpnConfig LoadConfig(string arg) =>
        VpnConfig.Parse(File.Exists(arg) ? File.ReadAllText(arg) : arg);

    private static int Handshake(string[] rest)
    {
        if (rest.Length < 1) return Usage();
        var cfg = LoadConfig(rest[0]);
        var tunnel = new VpnTunnel();
        tunnel.LogLine += l => Console.WriteLine($"  {l}");
        Console.WriteLine($"Handshake test -> {cfg.ServerAddress}:{cfg.Port} ({cfg.Protocol}/{cfg.WireMode})");
        try
        {
            var ip = tunnel.TestHandshake(cfg);
            Console.WriteLine($"RESULT: OK, server assigned tunnel IP {ip}");
            return 0;
        }
        catch (Exception e)
        {
            Console.WriteLine($"RESULT: FAILED — {e.GetType().Name}: {e.Message}");
            return 1;
        }
    }

    private static int Connect(string[] rest)
    {
        if (rest.Length < 1) return Usage();
        var cfg = LoadConfig(rest[0]);
        int seconds = rest.Length >= 2 && int.TryParse(rest[1], out int s) ? s : 30;
        var tunnel = new VpnTunnel();
        tunnel.LogLine += l => Console.WriteLine($"  {l}");
        tunnel.StatusChanged += (st, extra) => Console.WriteLine($"  [status] {st} {extra}");
        Console.WriteLine($"Connecting full tunnel -> {cfg.ServerAddress}:{cfg.Port} for {seconds}s (needs root)");
        tunnel.Start(cfg);
        Thread.Sleep(seconds * 1000);
        tunnel.Stop();
        Console.WriteLine("Stopped.");
        return 0;
    }

    private static int GenAssets(string[] rest)
    {
        string dir = rest.Length >= 1 ? rest[0] : "assets";
        Directory.CreateDirectory(dir);
        File.WriteAllBytes(Path.Combine(dir, "appicon.png"), Branding.AppIconPng(1024));
        File.WriteAllBytes(Path.Combine(dir, "logo.png"), Branding.LogoPng(512));
        File.WriteAllBytes(Path.Combine(dir, "tray_disconnected.png"), Branding.TrayPng(Branding.StatusDisconnected));
        File.WriteAllBytes(Path.Combine(dir, "tray_connecting.png"), Branding.TrayPng(Branding.StatusConnecting));
        File.WriteAllBytes(Path.Combine(dir, "tray_connected.png"), Branding.TrayPng(Branding.StatusConnected));
        File.WriteAllBytes(Path.Combine(dir, "tray_error.png"), Branding.TrayPng(Branding.StatusError));
        Console.WriteLine($"Wrote brand PNGs to: {Path.GetFullPath(dir)}");
        return 0;
    }

    private static int GenIcns(string[] rest)
    {
        string path = rest.Length >= 1 ? rest[0] : "Qeli.icns";
        var dir = Path.GetDirectoryName(Path.GetFullPath(path));
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
        Branding.WriteIcns(path, Branding.IcnsEntries);
        Console.WriteLine($"Wrote icns: {Path.GetFullPath(path)}");
        return 0;
    }
}
