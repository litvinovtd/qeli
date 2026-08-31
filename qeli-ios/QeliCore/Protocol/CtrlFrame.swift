import Foundation

/// In-tunnel control frames — small typed messages carried as ordinary AEAD records alongside
/// the IP packets. Port of `qeli/src/protocol/ctrl.rs`.
///
/// Why in-tunnel: the one thing that needs sending — the tunnel MTU this client settled on — is
/// only known AFTER the handshake (on UDP it comes out of the path-MTU probe), so no handshake
/// field can carry it. Riding inside the tunnel also means the frame inherits the session's AEAD
/// and replay protection, instead of being a bare datagram whose only identity is a source
/// address anyone could spoof.
///
/// Wire: `[0xC1][0x9B][type(1)][len(1)][body(len)]`. The tunnel's plaintext is otherwise an IP
/// packet (or empty, for the heartbeat); `0xC1`'s high nibble is `0xC`, which is neither 4 nor 6,
/// so a control frame can never be confused with IPv4/IPv6 in either direction.
///
/// Additive: a server that predates this has no branch for the frame and discards it as a
/// malformed packet, keeping its profile MTU — exactly its old behaviour. Nothing waits for a
/// reply.
enum CtrlFrame {
    static let magic: [UInt8] = [0xC1, 0x9B]
    /// magic(2) + type(1) + len(1)
    static let headerLength = 4
    /// Client→server MTU report. Body: `[mtu(2 BE)]`.
    static let typeMTUReport: UInt8 = 1

    /// Client→server: what this build is, so `list-clients` and the panel can answer "who still
    /// needs to update?". Body: `[verLen(1)][version][platform]`.
    ///
    /// SELF-REPORTED, NOT ATTESTED. Any authenticated peer can claim any string, so this is
    /// diagnostics only and must never gate anything.
    static let typeClientInfo: UInt8 = 2

    // Caps mirror ctrl.rs. Deliberately small: the value is peer-chosen and ends up in a CLI
    // table, the JSON API, the panel's DOM and the log.
    static let maxVersionLength = 32
    static let maxPlatformLength = 16

    /// The platform tag this build reports. A closed set, like ctrl.rs.
    static let platform = "ios"

    /// Semver plus the punctuation real builds use. The server refuses anything else OUTRIGHT
    /// rather than scrubbing it, so a frame it would reject must not be built here either.
    private static func validVersion(_ s: String) -> Bool {
        !s.isEmpty && s.count <= maxVersionLength && s.utf8.allSatisfy { b in
            (b >= 0x30 && b <= 0x39) || (b >= 0x41 && b <= 0x5A) || (b >= 0x61 && b <= 0x7A)
                || b == 0x2E || b == 0x2D || b == 0x2B || b == 0x5F   // . - + _
        }
    }

    /// A short lowercase identifier: linux, windows, macos, android, ios, …
    private static func validPlatform(_ s: String) -> Bool {
        !s.isEmpty && s.count <= maxPlatformLength && s.utf8.allSatisfy { b in
            (b >= 0x61 && b <= 0x7A) || (b >= 0x30 && b <= 0x39) || b == 0x2D
        }
    }

    /// Build the client-info frame, or nil when either field breaks the caps or the charset —
    /// the caller then sends nothing and the server shows the session as unknown, which is
    /// exactly the pre-feature behaviour.
    // The default must be QUALIFIED: an unqualified `platform` here would resolve to the
    // parameter being declared, not the static property.
    static func clientInfo(version: String, platform: String = CtrlFrame.platform) -> Data? {
        guard validVersion(version), validPlatform(platform) else { return nil }
        let v = Array(version.utf8)
        let p = Array(platform.utf8)
        let bodyLength = 1 + v.count + p.count
        guard bodyLength <= Int(UInt8.max) else { return nil }

        var frame = Data(magic)
        frame.append(typeClientInfo)
        frame.append(UInt8(bodyLength))
        frame.append(UInt8(v.count))
        frame.append(contentsOf: v)
        frame.append(contentsOf: p)
        return frame
    }

    /// This build's own client-info frame: the bundle version (the one source that cannot drift
    /// from `project.yml` — see ``AppConstants/version``) plus ``platform``.
    static func thisBuild() -> Data? {
        clientInfo(version: AppConstants.version)
    }

    /// Build the MTU report frame for `mtu`.
    static func mtuReport(_ mtu: Int) -> Data {
        let clamped = UInt16(min(max(mtu, 0), Int(UInt16.max)))
        var frame = Data(magic)
        frame.append(typeMTUReport)
        frame.append(2)
        frame.append(UInt8(clamped >> 8))
        frame.append(UInt8(clamped & 0xFF))
        return frame
    }

    /// True if a decrypted tunnel plaintext is a control frame, not an IP packet.
    static func isCtrl(_ plaintext: Data) -> Bool {
        plaintext.count >= headerLength
            && plaintext[plaintext.startIndex] == magic[0]
            && plaintext[plaintext.index(plaintext.startIndex, offsetBy: 1)] == magic[1]
    }
}
