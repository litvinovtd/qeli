import unittest
from audit_android_trusted_lockdown import connected_ssid, has_location_foreground_type

class ObservedSsidTests(unittest.TestCase):
    def test_current_connected_ssid_ignores_other_diagnostic_fields(self):
        self.assertEqual("AndroidWifi", connected_ssid('Wifi is enabled\nWifi is connected to "AndroidWifi"\nWifiInfo: SSID: "other"'))
    def test_absent_or_redacted_ssid_is_rejected(self):
        for text in ('Wifi is enabled', 'Wifi is connected to "<unknown ssid>"', 'Wifi is connected to ""'):
            with self.subTest(text=text), self.assertRaises(ValueError): connected_ssid(text)
    def test_fixture_does_not_pass_unsafe_or_unsupported_text_to_input(self):
        for ssid in ('a b','a;reboot','Г©','x'*33):
            with self.subTest(ssid=ssid), self.assertRaises(ValueError): connected_ssid('Wifi is connected to "'+ssid+'"')
class ForegroundTypeTests(unittest.TestCase):
    def test_observed_api34_hex_type_in_owned_active_service(self):
        self.assertTrue(has_location_foreground_type("User 0 active services:\n  * ServiceRecord{abcd u0 com.qeli/.VpnServiceImpl}\n    isForeground=true foregroundId=1001 types=40000008 foregroundNoti=Notification()"))
    def test_last_anr_or_other_service_cannot_supply_location_type(self):
        self.assertFalse(has_location_foreground_type("Last ANR service:\nServiceRecord{old u0 com.qeli/.VpnServiceImpl}\n isForeground=true foregroundId=1001 types=40000008\nUser 0 active services:\n  * ServiceRecord{other u0 other/.Service}\n isForeground=true foregroundId=1 types=8"))
    def test_missing_or_non_location_type_is_rejected(self):
        for value in ("", "isForeground=true foregroundId=1001 types=40000000", "isForeground=false foregroundId=1001 types=40000008"):
            self.assertFalse(has_location_foreground_type("User 0 active services:\n  * ServiceRecord{a u0 com.qeli/.VpnServiceImpl}\n"+value))

if __name__ == '__main__': unittest.main()
