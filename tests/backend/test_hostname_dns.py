import json
import unittest
from dataclasses import replace

from omarchy_wireguard.controller import Controller
from omarchy_wireguard.nftables import FirewallContext
from omarchy_wireguard.system import HostSystem, SystemFailure, bootstrap_hostname
from test_controller import FakeSystem, MemoryStore, PROFILE


class DnsRunner:
    def __init__(self):
        self.state = {"eth0": (("original.test", "~."), True)}
        self.missing_dns = False

    def run(self, argv, **kwargs):
        if argv == ["ip", "-json", "link", "show"]:
            return json.dumps([{"ifname": "eth0"}])
        _command, operation, interface, *values = argv
        domains, default_route = self.state[interface]
        if operation == "domain":
            if values:
                self.state[interface] = (tuple(values), default_route)
            return "Link: " + " ".join(domains)
        if operation == "default-route":
            if values:
                self.state[interface] = (domains, values[0] == "yes")
            return "Link: " + ("yes" if default_route else "no")
        if operation == "dns":
            return "Link: " + ("" if self.missing_dns else "192.0.2.53")
        raise AssertionError(argv)


class DnsSystem(FakeSystem):
    def __init__(self):
        super().__init__()
        self.runner = DnsRunner()
        real = HostSystem(self.runner)
        self.configure_lan_dns = real.configure_lan_dns
        self.capture_lan_dns = real.capture_lan_dns
        self.restore_lan_dns = real.restore_lan_dns
        self.resolved_hosts = []

    def inspect_firewall_context(self, timeout=10):
        return replace(super().inspect_firewall_context(timeout),
                       physical_interfaces=("eth0",))

    def resolve_endpoint(self, host, port, timeout=10):
        self.resolved_hosts.append(host)
        if self.runner.state["eth0"] != (("~lan", "~" + host), False):
            raise SystemFailure("endpoint route is missing")
        return (("192.0.2.4", port),)

    def activate(self, uuid, timeout):
        host = self.resolved_hosts[-1]
        if self.runner.state["eth0"] != (("~lan", "~" + host), False):
            raise SystemFailure("endpoint route disappeared before activation")
        return super().activate(uuid, timeout)


class HostnameDnsTests(unittest.TestCase):
    def controller(self):
        profile = {**PROFILE, "endpoint_host": "vpn.example.test"}
        system = DnsSystem()
        controller = Controller(MemoryStore({"profiles.json": [profile]}), system,
                                sleeper=lambda _seconds: None)
        return controller, system

    def test_temporary_route_survives_activation_then_is_removed(self):
        controller, system = self.controller()
        controller.connect({"city": "Japan/Tokyo"})
        controller.tick()
        self.assertEqual(controller.mode, "connected")
        self.assertEqual(system.resolved_hosts, ["vpn.example.test"])
        self.assertEqual(system.runner.state["eth0"], (("~lan",), False))
        self.assertEqual(controller.dns_restore,
                         (("eth0", ("original.test", "~."), True),))

    def test_failure_removes_temporary_route_and_keeps_original_snapshot(self):
        controller, system = self.controller()
        system.fail_activate = True
        controller.connect({"city": "Japan/Tokyo"})
        controller.tick()
        self.assertEqual(controller.mode, "failed")
        self.assertEqual(system.runner.state["eth0"], (("~lan",), False))
        self.assertEqual(controller.dns_restore,
                         (("eth0", ("original.test", "~."), True),))

    def test_missing_physical_dns_stops_before_resolution(self):
        controller, system = self.controller()
        system.runner.missing_dns = True
        controller.connect({"city": "Japan/Tokyo"})
        controller.tick()
        self.assertEqual(controller.mode, "failed")
        self.assertEqual(system.resolved_hosts, [])

    def test_invalid_hostnames_are_rejected_without_side_effects(self):
        for host in ("~.", "localhost", "bad_name.test", "a.test\n~."):
            with self.subTest(host=host):
                with self.assertRaises(SystemFailure):
                    bootstrap_hostname(host)

    def test_numeric_endpoint_needs_no_bootstrap_route(self):
        self.assertIsNone(bootstrap_hostname("192.0.2.1"))
        runner = DnsRunner()
        HostSystem(runner).configure_lan_dns(
            FirewallContext(physical_interfaces=("eth0",)), endpoint_host="192.0.2.1")
        self.assertEqual(runner.state["eth0"], (("~lan",), False))


if __name__ == "__main__":
    unittest.main()
