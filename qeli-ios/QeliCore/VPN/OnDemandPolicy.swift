import NetworkExtension

/// Side-effect-free construction and inspection of the system On-Demand rule set.
/// The entitled container app uses this helper from every lifecycle entry point, so a
/// queued widget command cannot install a policy different from a foreground action.
enum OnDemandPolicy {
    static func makeRules(settings: AppSettings) -> [NEOnDemandRule] {
        guard settings.onDemandEnabled, settings.connectionDesired else { return [] }
        var rules: [NEOnDemandRule] = []
        let ssids = TrustedWiFiPolicy.normalized(settings.trustedWiFiSSIDs)
        if settings.trustedWiFiEnabled, !ssids.isEmpty {
            let disconnect = NEOnDemandRuleDisconnect()
            disconnect.interfaceTypeMatch = .wiFi
            disconnect.ssidMatch = ssids
            rules.append(disconnect)
        }
        rules.append(NEOnDemandRuleConnect())
        return rules
    }

    static func hasTrustedWiFiDisconnectRule(
        isOnDemandEnabled: Bool,
        rules: [NEOnDemandRule]
    ) -> Bool {
        guard isOnDemandEnabled else { return false }
        return rules.contains(where: { rule in
            rule is NEOnDemandRuleDisconnect
                && rule.interfaceTypeMatch == .wiFi
                && !(rule.ssidMatch?.isEmpty ?? true)
        })
    }
}
