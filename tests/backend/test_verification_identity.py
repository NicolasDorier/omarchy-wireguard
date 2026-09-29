"""Protection status must use exact observations, not substring matches."""

import json
import unittest

from omarchy_wireguard.nftables import FirewallContext
from omarchy_wireguard.system import HostSystem, SystemFailure
from test_system import FakeRunner


UUID = "00000000-0000-0000-0000-000000000001"


def verification(active="activated\nwg0\n", handshakes="peer\t950\n"):
    responses = {
        ("nmcli", "-g", "GENERAL.STATE,GENERAL.DEVICES", "connection", "show", "uuid", UUID): active,
        ("wg", "show", "wg0", "fwmark"): "0x6f7467\n",
        ("ip", "-json", "route", "get", "1.1.1.1"): json.dumps([{"dev": "wg0"}]),
        ("ip", "-6", "-json", "route", "get", "2606:4700:4700::1111"):
            SystemFailure("no IPv6 route"),
        ("nft", "list", "table", "inet", "omarchy_wireguard"):
            'table inet omarchy_wireguard { chain output { type filter hook output priority -10; policy drop; meta mark 0x6f7467; comment "WireGuard fail closed"; } }',
        ("resolvectl", "dns", "wg0"): "Link: 10.0.0.1\n",
        ("resolvectl", "domain", "wg0"): "Link: ~.\n",
        ("resolvectl", "domain", "eth0"): "Link: ~lan\n",
        ("resolvectl", "dns", "eth0"): "Link: 192.168.1.1\n",
        ("resolvectl", "default-route", "eth0"): "Link: no\n",
        ("wg", "show", "wg0", "latest-handshakes"): handshakes,
    }
    context = FirewallContext(physical_interfaces=("eth0",),
                              lan_dns_links=(("eth0", ("192.168.1.1",)),),
                              tunnel_dns=("10.0.0.1",))
    return HostSystem(FakeRunner(responses)).verify(
        UUID, "wg0", now=1000, firewall_context=context)


class VerificationIdentityTests(unittest.TestCase):
    def test_state_and_device_must_match_exactly(self):
        self.assertTrue(verification().ok)
        for active in ("deactivated\nwg0\n", "activated\nwg01\n",
                       "activated\nwg0,eth0\n", "activated\nwg0\neth0\n"):
            with self.subTest(active=active):
                self.assertFalse(verification(active=active).checks["profile_interface"])

    def test_rekey_window_and_future_handshakes(self):
        for age in (121, 150, 180):
            self.assertTrue(verification(handshakes=f"peer\t{1000 - age}\n").ok)
        for timestamp in (819, 1001):
            self.assertFalse(verification(handshakes=f"peer\t{timestamp}\n").checks["handshake_fresh"])


if __name__ == "__main__":
    unittest.main()
