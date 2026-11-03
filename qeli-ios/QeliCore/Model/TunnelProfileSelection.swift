import Foundation

/// Explicit launches are authoritative, including invalid/stale requests. Only an
/// absent one-shot request may use the profile persisted for automatic launches.
enum TunnelProfileSelection {
    static func resolve(requested: Any?, configured: Any?) -> UUID? {
        guard let text = (requested ?? configured) as? String else { return nil }
        return UUID(uuidString: text)
    }
}
