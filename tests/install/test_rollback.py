import pathlib
import subprocess
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]


class InstallRollbackTests(unittest.TestCase):
    def run_cleanup(self, reload_succeeds=True, stop_succeeds=True):
        source = (ROOT / "scripts/install-backend").read_text()
        cleanup = "cleanup() {" + source.split("cleanup() {", 1)[1].split(
            "\ntrap cleanup ERR", 1)[0]
        harness = r'''
set -eu
PATH=/no-external-commands
stage=""
backup=""
had_networkmanager_dropin=false
cached_dependency=true
networkmanager_active=true
firewall_stopped=false
firewall_removed=false
rm() { :; }
nft() { firewall_removed=true; }
systemctl() {
  if [[ $* == "daemon-reload" ]]; then
    [[ $reload_succeeds == true ]] || return 1
    cached_dependency=false
  elif [[ $* == *"disable --now"* && $* == *"omarchy-wireguard-firewall.service"* ]]; then
    [[ $stop_succeeds == true ]] || return 1
    firewall_stopped=true
    [[ $cached_dependency == false ]] || networkmanager_active=false
  fi
}
'''
        script = ("reload_succeeds=" + str(reload_succeeds).lower() + "\n"
                  + "stop_succeeds=" + str(stop_succeeds).lower() + "\n" + harness + cleanup
                  + '\ncleanup\nprintf "%s %s %s\\n" "$networkmanager_active" "$firewall_stopped" "$firewall_removed"\n')
        return subprocess.run(["/bin/bash", "--noprofile", "--norc", "-c", script],
                              env={"PATH": "/no-external-commands"}, capture_output=True,
                              text=True, timeout=5)

    def test_reload_detaches_dependency_before_firewall_stop(self):
        result = self.run_cleanup()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("true true true", result.stdout)

    def test_failed_reload_retains_firewall_and_networkmanager(self):
        result = self.run_cleanup(False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("true false false", result.stdout)

    def test_failed_service_stop_retains_firewall(self):
        result = self.run_cleanup(stop_succeeds=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("true false false", result.stdout)


if __name__ == "__main__":
    unittest.main()
