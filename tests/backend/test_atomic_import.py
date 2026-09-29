import base64
import unittest
from unittest.mock import patch

from omarchy_wireguard.importer import parse_config
from omarchy_wireguard.system import HostSystem, SystemFailure, _profile_keyfile


KEY = base64.b64encode(bytes([1]) * 32).decode()
UUID = "00000000-0000-0000-0000-000000000001"
NAME = "omarchy-wireguard-test"
CONFIG = f"""[Interface]
PrivateKey={KEY}
Address=10.77.0.2/24, 2001:db8::2/64
DNS=10.77.0.1, 2001:db8::1
ListenPort=51821
MTU=1400
[Peer]
PublicKey={KEY}
Endpoint=vpn.example.test:51820
AllowedIPs=0.0.0.0/0, ::/0
PersistentKeepalive=25
"""


class Runner:
    def __init__(self):
        self.calls = []
        self.existing = ""
        self.present = False
        self.identity = NAME
        self.identity_failures = 0

    def run(self, argv, **kwargs):
        self.calls.append(argv)
        if argv == ["nmcli", "-t", "-f", "UUID", "connection", "show"]:
            return self.existing
        if argv == ["nmcli", "-g", "connection.id", "connection", "show", "uuid", UUID]:
            if self.identity_failures:
                self.identity_failures -= 1
                raise SystemFailure("not visible yet")
            if not self.present:
                raise SystemFailure("not found")
            return self.identity
        if argv == ["nmcli", "connection", "delete", "uuid", UUID]:
            self.present = False
            return ""
        raise AssertionError(argv)


class AtomicImportTests(unittest.TestCase):
    def setUp(self):
        self.runner = Runner()
        self.profile = parse_config("test.conf", CONFIG)

    def publish(self, text):
        self.text = text
        self.runner.present = True

    def test_complete_keyfile_is_published_without_secret_argv(self):
        with patch("omarchy_wireguard.system.uuid_module.uuid4", return_value=UUID), patch(
                "omarchy_wireguard.system.publish_keyfile", side_effect=self.publish):
            self.assertEqual(HostSystem(self.runner).import_profile(self.profile, NAME), UUID)
        self.assertIn("autoconnect=false", self.text)
        self.assertIn("interface-name=owg-", self.text)
        self.assertIn("private-key=" + KEY, self.text)
        self.assertIn("allowed-ips=0.0.0.0/0;::/0;", self.text)
        self.assertNotIn(KEY, repr(self.runner.calls))
        self.assertFalse(any("import" in call or "modify" in call for call in self.runner.calls))

    def test_lost_publish_reply_rolls_back_only_matching_new_identity(self):
        def fail(text):
            self.publish(text)
            raise ValueError("reply lost")

        with patch("omarchy_wireguard.system.uuid_module.uuid4", return_value=UUID), patch(
                "omarchy_wireguard.system.publish_keyfile", side_effect=fail):
            with self.assertRaises(SystemFailure):
                HostSystem(self.runner).import_profile(self.profile, NAME)
        self.assertFalse(self.runner.present)

        self.runner.present = False
        self.runner.identity = "unrelated"
        with patch("omarchy_wireguard.system.uuid_module.uuid4", return_value=UUID), patch(
                "omarchy_wireguard.system.publish_keyfile", side_effect=self.publish):
            with self.assertRaises(SystemFailure):
                HostSystem(self.runner).import_profile(self.profile, NAME)
        self.assertTrue(self.runner.present)

    def test_delayed_publication_is_found_and_rolled_back(self):
        def fail(text):
            self.publish(text)
            self.runner.identity_failures = 2
            raise ValueError("reply lost")

        with patch("omarchy_wireguard.system.uuid_module.uuid4", return_value=UUID), patch(
                "omarchy_wireguard.system.publish_keyfile", side_effect=fail), patch(
                "omarchy_wireguard.system.time.sleep") as sleep:
            with self.assertRaises(SystemFailure):
                HostSystem(self.runner).import_profile(self.profile, NAME)
        self.assertFalse(self.runner.present)
        self.assertEqual(sleep.call_count, 2)

    def test_existing_uuid_is_never_published(self):
        self.runner.existing = UUID + "\n"
        with patch("omarchy_wireguard.system.uuid_module.uuid4", return_value=UUID), patch(
                "omarchy_wireguard.system.publish_keyfile") as publish:
            with self.assertRaises(SystemFailure):
                HostSystem(self.runner).import_profile(self.profile, NAME)
        publish.assert_not_called()

    def test_key_and_numeric_validation_precede_publication(self):
        malformed = parse_config("test.conf", CONFIG.replace(KEY, "not-a-key"))
        with patch("omarchy_wireguard.system.publish_keyfile") as publish:
            with self.assertRaises(SystemFailure):
                HostSystem(self.runner).import_profile(malformed, NAME)
        publish.assert_not_called()
        for field, original, invalid in (("ListenPort", 51821, 65536),
                                         ("MTU", 1400, 4294967296)):
            profile = parse_config(
                "test.conf", CONFIG.replace(f"{field}={original}", f"{field}={invalid}"))
            with self.assertRaises(SystemFailure):
                _profile_keyfile(profile, NAME, UUID, None)

    def test_dns_requires_an_address_of_the_same_family(self):
        config = CONFIG.replace(", 2001:db8::2/64", "")
        with self.assertRaisesRegex(SystemFailure, "invalid WireGuard profile"):
            _profile_keyfile(parse_config("test.conf", config), NAME, UUID, None)


if __name__ == "__main__":
    unittest.main()
