import Foundation
#if canImport(QeliNative)
import QeliNative
#endif

/// Pure ABI 1.16 document/policy service; profile text remains INI.
enum ConfigCore {
    static func call(_ request: [String: Any]) throws -> [String: Any] {
#if canImport(QeliNative)
        let abi = qeli_client_abi_version()
        guard abi >> 16 == 1, abi & 65535 >= 16 else {
            throw QeliNativeError.invalidInput("Configuration editor requires native ABI 1.16 or newer.")
        }
        var input = try JSONSerialization.data(withJSONObject: request)
        defer { input.resetBytes(in: 0..<input.count) }
        guard input.count <= 2 * 1024 * 1024 else { throw QeliNativeError.invalidInput("Configuration request too large.") }
        var output = Data(count: 4096)
        defer { output.resetBytes(in: 0..<output.count) }
        var size = 0
        func invoke() -> Int32 {
            let capacity = output.count
            return input.withUnsafeBytes { source in output.withUnsafeMutableBytes { target in
                qeli_config_request(source.bindMemory(to: UInt8.self).baseAddress, input.count,
                                    target.bindMemory(to: UInt8.self).baseAddress, capacity, &size)
            } }
        }
        var status = invoke()
        if status == -6 {
            guard size <= 4 * 1024 * 1024 else { throw QeliNativeError.invalidInput("Configuration response too large.") }
            output.resetBytes(in: 0..<output.count)
            output = Data(count: size)
            status = invoke()
        }
        guard status == 0, size <= output.count else { throw QeliNativeError.operationFailed("configuration ABI (\(status))") }
        let envelope = try JSONSerialization.jsonObject(with: output.prefix(size)) as? [String: Any]
        guard envelope?["ok"] as? Bool == true, let result = envelope?["result"] as? [String: Any] else {
            throw VPNConfigError.invalid(envelope?["error"] as? String ?? "Invalid configuration response.")
        }
        return result
#else
        throw QeliNativeError.unavailable
#endif
    }
    static func policy(_ operation: String, _ data: [String: Any] = [:]) throws -> [String: Any] {
        try call(["version":1, "op":"policy", "operation":operation, "data":data])
    }
}
