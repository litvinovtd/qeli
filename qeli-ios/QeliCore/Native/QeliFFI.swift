import Foundation

enum QeliNativeError: LocalizedError {
    case unavailable
    case invalidInput(String)
    case operationFailed(String)

    var errorDescription: String? {
        switch self {
        case .unavailable: return "The Qeli iOS native core has not been linked."
        case .invalidInput(let message): return message
        case .operationFailed(let operation): return "Native Qeli operation failed: \(operation)."
        }
    }
}

#if canImport(QeliNative)
import QeliNative

enum QeliNativeCore {
    static let isAvailable = true

    static func fakeTLSClientHello(
        x25519PublicKey: Data,
        mlkemEncapsulationKey: Data,
        sni: String,
        padToMinimum: Int
    ) throws -> Data {
        guard x25519PublicKey.count == 32 else {
            throw QeliNativeError.invalidInput("X25519 public key must be 32 bytes.")
        }
        var output: UnsafeMutablePointer<UInt8>?
        var outputLength = 0
        let status: Int32 = x25519PublicKey.withUnsafeBytes { xBytes in
            mlkemEncapsulationKey.withUnsafeBytes { mlBytes in
                sni.withCString { sniPointer in
                    qeli_build_faketls_clienthello(
                        xBytes.bindMemory(to: UInt8.self).baseAddress,
                        mlBytes.bindMemory(to: UInt8.self).baseAddress,
                        mlkemEncapsulationKey.count,
                        sniPointer,
                        max(0, padToMinimum),
                        &output,
                        &outputLength
                    )
                }
            }
        }
        guard status == 0 else { throw QeliNativeError.operationFailed("fake ClientHello") }
        return takeBuffer(output, length: outputLength)
    }

    fileprivate static func takeBuffer(_ pointer: UnsafeMutablePointer<UInt8>?, length: Int) -> Data {
        guard let pointer, length > 0 else { return Data() }
        let value = Data(bytes: pointer, count: length)
        qeli_realtls_buf_free(pointer, length)
        return value
    }
}

final class MLKEMContext {
    private var handle: UnsafeMutableRawPointer?
    let encapsulationKey: Data

    init() throws {
        var output: UnsafeMutablePointer<UInt8>?
        var outputLength = 0
        handle = qeli_mlkem_keygen(&output, &outputLength)
        guard handle != nil else { throw QeliNativeError.operationFailed("ML-KEM key generation") }
        encapsulationKey = QeliNativeCore.takeBuffer(output, length: outputLength)
    }

    deinit { if let handle { qeli_mlkem_free(handle) } }

    func decapsulate(_ ciphertext: Data) throws -> Data {
        guard let handle else { throw QeliNativeError.operationFailed("ML-KEM context is closed") }
        var output: UnsafeMutablePointer<UInt8>?
        var outputLength = 0
        let status = ciphertext.withUnsafeBytes { bytes in
            qeli_mlkem_decapsulate(
                handle,
                bytes.bindMemory(to: UInt8.self).baseAddress,
                ciphertext.count,
                &output,
                &outputLength
            )
        }
        guard status == 0 else { throw QeliNativeError.operationFailed("ML-KEM decapsulation") }
        return QeliNativeCore.takeBuffer(output, length: outputLength)
    }
}

final class RealTLSClient {
    enum Progress { case needsMore, established(Data) }
    private var handle: UnsafeMutableRawPointer?
    let clientHello: Data

    init(realityPublicKey: Data, shortID: Data, sni: String) throws {
        guard realityPublicKey.count == 32 else {
            throw QeliNativeError.invalidInput("REALITY public key must be 32 bytes.")
        }
        guard shortID.count == 8 else {
            throw QeliNativeError.invalidInput("REALITY short ID must be 8 bytes.")
        }
        var output: UnsafeMutablePointer<UInt8>?
        var outputLength = 0
        handle = realityPublicKey.withUnsafeBytes { keyBytes in
            shortID.withUnsafeBytes { shortBytes in
                sni.withCString { sniPointer in
                    qeli_realtls_new(
                        keyBytes.bindMemory(to: UInt8.self).baseAddress,
                        shortBytes.bindMemory(to: UInt8.self).baseAddress,
                        sniPointer,
                        &output,
                        &outputLength
                    )
                }
            }
        }
        guard handle != nil else { throw QeliNativeError.operationFailed("REALITY initialization") }
        clientHello = QeliNativeCore.takeBuffer(output, length: outputLength)
    }

    deinit { if let handle { qeli_realtls_free(handle) } }

    func receiveHandshake(_ data: Data) throws -> Progress {
        let (status, output) = try call(data, function: qeli_realtls_recv)
        switch status {
        case 0: return .needsMore
        case 1: return .established(output)
        default: throw QeliNativeError.operationFailed("REALITY handshake")
        }
    }

    func seal(_ plaintext: Data) throws -> Data {
        let (status, output) = try call(plaintext, function: qeli_realtls_seal)
        guard status == 0 else { throw QeliNativeError.operationFailed("REALITY seal") }
        return output
    }

    func open(_ records: Data) throws -> Data {
        let (status, output) = try call(records, function: qeli_realtls_open)
        guard status == 0 else { throw QeliNativeError.operationFailed("REALITY open") }
        return output
    }

    private func call(
        _ input: Data,
        function: (UnsafeMutableRawPointer?, UnsafePointer<UInt8>?, Int, UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?, UnsafeMutablePointer<Int>?) -> Int32
    ) throws -> (Int32, Data) {
        guard let handle else { throw QeliNativeError.operationFailed("REALITY context is closed") }
        var output: UnsafeMutablePointer<UInt8>?
        var outputLength = 0
        let status = input.withUnsafeBytes { bytes in
            function(
                handle,
                bytes.bindMemory(to: UInt8.self).baseAddress,
                input.count,
                &output,
                &outputLength
            )
        }
        return (status, QeliNativeCore.takeBuffer(output, length: outputLength))
    }
}

#elseif QELI_NATIVE_REQUIRED

#error("QeliNative is required by the Packet Tunnel target. Run 'sh build_native.sh' before generating the Xcode project.")

#else

enum QeliNativeCore {
    static let isAvailable = false

    static func fakeTLSClientHello(
        x25519PublicKey: Data,
        mlkemEncapsulationKey: Data,
        sni: String,
        padToMinimum: Int
    ) throws -> Data {
        throw QeliNativeError.unavailable
    }
}

final class MLKEMContext {
    let encapsulationKey = Data()
    init() throws { throw QeliNativeError.unavailable }
    func decapsulate(_ ciphertext: Data) throws -> Data { throw QeliNativeError.unavailable }
}

final class RealTLSClient {
    enum Progress { case needsMore, established(Data) }
    let clientHello = Data()
    init(realityPublicKey: Data, shortID: Data, sni: String) throws { throw QeliNativeError.unavailable }
    func receiveHandshake(_ data: Data) throws -> Progress { throw QeliNativeError.unavailable }
    func seal(_ plaintext: Data) throws -> Data { throw QeliNativeError.unavailable }
    func open(_ records: Data) throws -> Data { throw QeliNativeError.unavailable }
}

#endif
