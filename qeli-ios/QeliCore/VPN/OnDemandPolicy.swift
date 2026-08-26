import NetworkExtension

/// Side-effect-free construction and inspection of the system On-Demand rule set.
/// Both the container app and the widget extension use this implementation so a silent
/// widget action cannot install a policy different from a foreground action.
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
