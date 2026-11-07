//! Preserve address acquisition and link-local control when router traffic is managed.
pub(super) fn nft() -> &'static str {
    " udp sport { 67, 68 } udp dport { 67, 68 } return\n udp sport { 546, 547 } udp dport { 546, 547 } return\n icmpv6 type { 130, 131, 132, 133, 134, 135, 136, 143 } return\n"
}
pub(super) fn iptables(chain: &str, v6: bool, tag: &str) -> String {
    if v6 {
        let mut text =
            format!("-A {chain} -p udp --sport 546:547 --dport 546:547 {tag} -j RETURN\n");
        for kind in [130, 131, 132, 133, 134, 135, 136, 143] {
            text.push_str(&format!(
                "-A {chain} -p ipv6-icmp --icmpv6-type {kind} {tag} -j RETURN\n"
            ));
        }
        text
    } else {
        format!("-A {chain} -p udp --sport 67:68 --dport 67:68 {tag} -j RETURN\n")
    }
}
