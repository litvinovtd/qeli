import ipaddress
import struct
import unittest

import tap_ipv6_control_probe as probe


class TapIpv6ControlProbeTest(unittest.TestCase):
    def frame(self, source, destination, body, source_mac=b"\x02\0\0\0\0\x01"):
        return probe.ethernet_ipv6(
            source_mac,
            bytes.fromhex("333300000001"),
            ipaddress.IPv6Address(source),
            ipaddress.IPv6Address(destination),
            body,
        )

    def test_router_and_neighbor_solicitations_have_valid_checksums(self):
        mac = bytes.fromhex("02aabbccddee")
        rs = probe.router_solicitation(mac)
        source, destination, payload = probe.ipv6_icmp(rs)
        self.assertEqual(source, ipaddress.IPv6Address("::"))
        self.assertEqual(destination, probe.ALL_ROUTERS)
        self.assertEqual(payload[0], 133)

        ns = probe.neighbor_solicitation(
            mac, ipaddress.IPv6Address("fd86::2"), ipaddress.IPv6Address("fd86::1")
        )
        source, destination, payload = probe.ipv6_icmp(ns)
        self.assertEqual(source, ipaddress.IPv6Address("fd86::2"))
        self.assertEqual(destination, ipaddress.IPv6Address("ff02::1:ff00:1"))
        self.assertEqual(payload[0], 135)

    def test_validates_ra_without_default_or_slaac(self):
        prefix = ipaddress.IPv6Network("fd86::/64")
        option = bytearray(32)
        option[0:4] = bytes((3, 4, 64, 0x80))
        option[4:8] = (3600).to_bytes(4, "big")
        option[8:12] = (1800).to_bytes(4, "big")
        option[16:32] = prefix.network_address.packed
        body = struct.pack("!BBHBBHII", 134, 0, 0, 64, 0, 0, 0, 0) + option
        frame = self.frame("fe80::ff:fe00:1", "ff02::1", body)
        self.assertEqual(probe.validate_ra(frame, prefix)["prefix"], "fd86::/64")

        routed = bytearray(frame)
        routed[60:62] = (30).to_bytes(2, "big")
        source = ipaddress.IPv6Address(bytes(routed[22:38]))
        destination = ipaddress.IPv6Address(bytes(routed[38:54]))
        payload = bytes(routed[54:])
        routed[56:58] = b"\0\0"
        routed[56:58] = struct.pack(
            "!H",
            probe.checksum(source.packed + destination.packed + struct.pack("!I3xB", len(payload), 58) + bytes(routed[54:])),
        )
        with self.assertRaisesRegex(ValueError, "default route"):
            probe.validate_ra(bytes(routed), prefix)

    def test_validates_neighbor_advertisement_target(self):
        target = ipaddress.IPv6Address("fd86::1")
        body = struct.pack("!BBHI16sBB6s", 136, 0, 0, 0x60000000, target.packed, 2, 1, bytes.fromhex("020000000001"))
        frame = self.frame(str(target), "fd86::2", body)
        self.assertEqual(probe.validate_na(frame, target)["target"], str(target))
        with self.assertRaisesRegex(ValueError, "source/target"):
            probe.validate_na(frame, ipaddress.IPv6Address("fd86::9"))


if __name__ == "__main__":
    unittest.main()
