/// Decisions for usable NWPath observations. The controller owns task cancellation and
/// generation checks; this policy keeps duplicate callbacks from cancelling useful work.
enum IOSRoamingObservationPolicy {
    enum Action: Equatable {
        case keep
        case establishBaseline
        case submit
    }

    static func usablePathAction(
        previousSignature: String?,
        signature: String,
        waitingForReplacement: Bool
    ) -> Action {
        // Even unchanged interface/address facts can hide a replacement NAT mapping.
        if waitingForReplacement { return .submit }
        guard let previousSignature else { return .establishBaseline }
        return signature == previousSignature ? .keep : .submit
    }
}
