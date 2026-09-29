import importlib.machinery
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
loader = importlib.machinery.SourceFileLoader(
    "wireguard_emergency_cli", str(ROOT / "bin/omarchy-wireguard"))
spec = importlib.util.spec_from_loader(loader.name, loader)
cli = importlib.util.module_from_spec(spec)
loader.exec_module(cli)


class EmergencyTests(unittest.TestCase):
    def invoke(self, nft_returncode=0, nft_output=None):
        output = nft_output
        if output is None:
            output = json.dumps({"nftables": [{"metainfo": {"json_schema_version": 1}}]})

        def run(argv, **kwargs):
            result = ""
            returncode = 0
            if argv == ["systemctl", "is-active", "--quiet", "omarchy-wireguard.service"]:
                returncode = 3
            elif argv[:2] == ["nmcli", "-t"]:
                result = ""
            elif argv == ["ip", "-json", "link", "show"]:
                result = "[]"
            elif argv == ["nft", "-j", "list", "tables"]:
                returncode, result = nft_returncode, output
            if kwargs.get("check") and returncode:
                raise subprocess.CalledProcessError(returncode, argv)
            return subprocess.CompletedProcess(argv, returncode, stdout=result, stderr="")

        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            original_path = cli.Path

            def mapped(value):
                return state if str(value) == "/var/lib/omarchy-wireguard" else original_path(value)

            with patch.object(cli.os, "geteuid", return_value=0), patch.object(
                    cli, "Path", side_effect=mapped), patch.object(
                    cli.subprocess, "run", side_effect=run):
                return cli.emergency_disable()

    def test_requires_readable_structured_firewall_observation(self):
        with self.assertRaisesRegex(cli.CliError, "verify.*firewall"):
            self.invoke(nft_returncode=1)
        for malformed in ("not json", "{}", '{"nftables":[null]}',
                          '{"nftables":[{"table":{}}]}'):
            with self.subTest(malformed=malformed), self.assertRaises(cli.CliError):
                self.invoke(nft_output=malformed)

    def test_reports_verified_absence_only(self):
        self.assertTrue(self.invoke()["ok"])
        with self.assertRaisesRegex(cli.CliError, "still active"):
            self.invoke(nft_output=json.dumps({"nftables": [
                {"table": {"family": "inet", "name": "omarchy_wireguard"}}]}))


if __name__ == "__main__":
    unittest.main()
