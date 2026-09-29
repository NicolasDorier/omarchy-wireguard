import json
import os
import socket
import unittest
from unittest.mock import patch

from omarchy_wireguard.controller import RequestFailure
from omarchy_wireguard.daemon import _handle_connection, reconcile_early_firewall
from omarchy_wireguard.nftables import FirewallContext
from omarchy_wireguard.protocol import ProtocolError
from omarchy_wireguard.system import SystemFailure


class Store:
    def __init__(self, state=None, error=None, dns=None):
        self.state = state
        self.error = error
        self.dns = dns or []

    def read(self, name, default):
        if self.error and name == "state.json":
            raise self.error
        if name == "state.json":
            return self.state
        if name == "dns.json":
            return self.dns
        return {}


class System:
    def __init__(self):
        self.removed = 0
        self.applied = 0

    def remove_firewall(self):
        self.removed += 1

    def inspect_firewall_context(self):
        return FirewallContext()

    def apply_firewall(self, context):
        self.applied += 1


class EarlyFirewallTests(unittest.TestCase):
    def test_missing_and_disabled_state_remove_policy(self):
        for state in (None, {"enabled": False, "target": None, "mru": []}):
            system = System()
            reconcile_early_firewall(Store(state), system)
            self.assertEqual((system.removed, system.applied), (1, 0))

    def test_enabled_state_fails_closed(self):
        system = System()
        reconcile_early_firewall(Store({"enabled": True, "target": "Japan/Tokyo", "mru": []}), system)
        self.assertEqual((system.removed, system.applied), (0, 1))

    def test_disabled_state_with_pending_dns_restore_fails_closed(self):
        system = System()
        store = Store({"enabled": False, "target": None, "mru": []},
                      dns=[["eth0", ["~."], True]])
        reconcile_early_firewall(store, system)
        self.assertEqual((system.removed, system.applied), (0, 1))

    def test_missing_state_with_pending_dns_restore_fails_closed(self):
        system = System()
        reconcile_early_firewall(Store(dns=[["eth0", ["~."], True]]), system)
        self.assertEqual((system.removed, system.applied), (0, 1))

    def test_corrupt_or_unsafe_state_fails_closed(self):
        for store in (Store({"enabled": "yes"}), Store(error=RuntimeError("unsafe"))):
            system = System()
            reconcile_early_firewall(store, system)
            self.assertEqual((system.removed, system.applied), (0, 1))

    def test_protocol_rejection_ignores_disconnected_client(self):
        with patch("omarchy_wireguard.daemon.peer_credentials",
                   side_effect=ProtocolError("bad peer")), patch(
                       "omarchy_wireguard.daemon.send_response", side_effect=BrokenPipeError):
            with self.assertLogs("omarchy-wireguard", level="WARNING"):
                _handle_connection(object(), object(), 1000)


class ControllerProbe:
    def __init__(self, error=None, emergency_error=None):
        self.error = error
        self.emergency_error = emergency_error
        self.calls = []
        self.emergencies = 0

    def handle(self, operation, args):
        self.calls.append((operation, args))
        if self.error:
            raise self.error
        return {"state": "connected"}

    def emergency(self):
        self.emergencies += 1
        if self.emergency_error:
            raise self.emergency_error


class ConnectionTests(unittest.TestCase):
    def request(self, controller, *, close=False):
        server, peer = socket.socketpair()
        with server, peer:
            peer.sendall(json.dumps({"op": "status", "request_id": "r1"}).encode() + b"\n")
            if close:
                peer.close()
            _handle_connection(server, controller, os.getuid())
            return b"" if close else peer.recv(4096)

    def test_lost_response_does_not_emergency_disconnect(self):
        controller = ControllerProbe()
        with self.assertLogs("omarchy-wireguard", level="WARNING"):
            self.request(controller, close=True)
        self.assertEqual(controller.calls, [("status", {})])
        self.assertEqual(controller.emergencies, 0)

    def test_controller_oserror_still_fails_closed(self):
        controller = ControllerProbe(OSError("secret"))
        with self.assertLogs("omarchy-wireguard", level="ERROR") as logs:
            response = json.loads(self.request(controller))
        self.assertEqual(controller.emergencies, 1)
        self.assertEqual(response["error"]["code"], "internal")
        self.assertNotIn("secret", "\n".join(logs.output))

    def test_emergency_cleanup_failure_does_not_escape_request_handler(self):
        controller = ControllerProbe(OSError("secret"), SystemFailure("cleanup secret"))
        with self.assertLogs("omarchy-wireguard", level="ERROR") as logs:
            response = json.loads(self.request(controller))
        self.assertEqual(response["error"]["code"], "internal")
        self.assertEqual(controller.emergencies, 1)
        self.assertNotIn("secret", "\n".join(logs.output))

    def test_rejection_does_not_trigger_emergency(self):
        controller = ControllerProbe(RequestFailure("no"))
        response = json.loads(self.request(controller))
        self.assertEqual(response["error"]["code"], "rejected")
        self.assertEqual(controller.emergencies, 0)


if __name__ == "__main__":
    unittest.main()
