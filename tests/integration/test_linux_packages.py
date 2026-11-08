"""What the client and mesh package scripts do to their service across install, upgrade and removal.

Release CI installs only the .deb, so the scripts run here in a POSIX shell against a stand-in
systemctl and a temporary root, following dpkg's and rpm's order of scripts.
"""
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
# Debian runs maintainer scripts with dash; prefer it where it is installed.
SHELL = shutil.which("dash") or shutil.which("sh")

SYSTEMCTL = """#!/bin/sh
# Stand-in for systemctl: records each call and keeps each unit's state as marker files.
echo "$*" >> "$FAKE_SYSTEMD/calls"
command= unit= now=
for argument in "$@"; do
    case $argument in
        --now) now=1 ;;
        -*) ;;
        *) if [ -z "$command" ]; then command=$argument; else unit=$argument; fi ;;
    esac
done
case $command in
    daemon-reload) ;;
    is-enabled) [ -e "$FAKE_SYSTEMD/$unit.enabled" ] ;;
    is-active) [ -e "$FAKE_SYSTEMD/$unit.active" ] ;;
    enable) : > "$FAKE_SYSTEMD/$unit.enabled"; [ -z "$now" ] || : > "$FAKE_SYSTEMD/$unit.active" ;;
    disable) rm -f "$FAKE_SYSTEMD/$unit.enabled"; [ -z "$now" ] || rm -f "$FAKE_SYSTEMD/$unit.active" ;;
    start | restart) : > "$FAKE_SYSTEMD/$unit.active" ;;
    stop) rm -f "$FAKE_SYSTEMD/$unit.active" ;;
    *) echo "systemctl stand-in: $command is not supported" >&2; exit 1 ;;
esac
"""

CLIENT = "ghostlinkd.service"
MESH = "ghostlink-mesh.service"
POSTINST = "packages/linux/scripts/client-postinstall.sh"
PRERM = "packages/linux/scripts/client-preremove.sh"
POSTRM = "packages/linux/scripts/client-postremove.sh"
POSTTRANS = "packages/linux/scripts/client-posttrans.sh"
MESH_POSTINST = "packages/linux/mesh/postinstall.sh"
MESH_PRERM = "packages/linux/mesh/preremove.sh"
MESH_POSTTRANS = "packages/linux/mesh/posttrans.sh"
# The settings file the client package installs, as scripts/build-linux.sh writes it.
TEMPLATE = re.search(r"cat > \"\$pkg/ghostlinkd\.env\" <<'EOF'\n(.*?\n)EOF\n",
                     (ROOT / "scripts/build-linux.sh").read_text(encoding="utf-8"), re.S).group(1)
OWNED = TEMPLATE.replace("GHOSTLINK_OWNER_UID=\n", "GHOSTLINK_OWNER_UID=1000\n")


@unittest.skipUnless(SHELL, "a POSIX shell is needed to run the Linux package scripts")
class LinuxPackageScripts(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.state = self.root / "systemd-state"
        for directory in ("bin", "etc/ghostlink", "run/systemd/system", "var/lib"):
            (self.root / directory).mkdir(parents=True)
        for name, text in (("systemctl", SYSTEMCTL), ("modprobe", "#!/bin/sh\nexit 0\n")):
            (self.root / "bin" / name).write_bytes(text.encode())
            (self.root / "bin" / name).chmod(0o755)
        self.env_file = self.root / "etc/ghostlink/ghostlinkd.env"
        self.reset(TEMPLATE)

    def reset(self, settings, unit=CLIENT, enabled=False, active=False):
        shutil.rmtree(self.state, ignore_errors=True)
        self.state.mkdir()
        self.env_file.write_bytes(settings.encode())
        for flag, wanted in (("enabled", enabled), ("active", active)):
            if wanted:
                (self.state / f"{unit}.{flag}").write_bytes(b"")

    def run_script(self, path, *arguments, sudo_uid=None):
        text = (ROOT / path).read_text(encoding="utf-8")
        for system in ("/etc/ghostlink", "/var/lib/ghostlink", "/run/systemd/system"):
            text = text.replace(system, self.root.as_posix() + system)
        script = self.root / Path(path).name
        script.write_bytes(text.encode())
        environment = {name: value for name, value in os.environ.items() if name != "SUDO_UID"}
        environment["PATH"] = str(self.root / "bin") + os.pathsep + environment.get("PATH", "")
        environment["FAKE_SYSTEMD"] = self.state.as_posix()
        if sudo_uid is not None:
            environment["SUDO_UID"] = sudo_uid
        result = subprocess.run([SHELL, script.as_posix(), *arguments], env=environment, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return result.stdout + result.stderr

    def is_on(self, unit, flag):
        return (self.state / f"{unit}.{flag}").exists()

    def calls(self):
        log = self.state / "calls"
        return [line.split()[0] for line in log.read_text().splitlines()] if log.exists() else []

    def settings(self):
        return self.env_file.read_bytes().decode()

    def test_a_first_install_takes_the_sudo_user_and_starts_the_service(self):
        for arguments in (("configure", ""), ("1",)):
            with self.subTest(arguments=arguments):
                self.reset(TEMPLATE)
                output = self.run_script(POSTINST, *arguments, sudo_uid="1000")
                self.assertEqual(self.settings(), OWNED)
                self.assertTrue(self.is_on(CLIENT, "enabled") and self.is_on(CLIENT, "active"))
                self.assertIn("installed for user ID 1000", output)

    def test_a_first_install_without_an_owner_leaves_the_service_off(self):
        for sudo_uid in (None, "0"):
            with self.subTest(sudo_uid=sudo_uid):
                self.reset(TEMPLATE)
                output = self.run_script(POSTINST, "configure", "", sudo_uid=sudo_uid)
                self.assertEqual(self.settings(), TEMPLATE)
                self.assertFalse(self.is_on(CLIENT, "enabled") or self.is_on(CLIENT, "active"))
                self.assertIn("Set GHOSTLINK_OWNER_UID", output)

    def test_an_owner_written_in_another_form_systemd_accepts_is_kept(self):
        for line in ('GHOSTLINK_OWNER_UID="1000"', "GHOSTLINK_OWNER_UID='1000'", "GHOSTLINK_OWNER_UID = 1000",
                     "  GHOSTLINK_OWNER_UID=1000\t ", "GHOSTLINK_OWNER_UID=1000\r"):
            with self.subTest(line=line):
                settings = TEMPLATE.replace("GHOSTLINK_OWNER_UID=\n", line + "\n")
                self.reset(settings)
                output = self.run_script(POSTINST, "configure", "", sudo_uid="1001")
                self.assertEqual(self.settings(), settings)
                self.assertIn("installed for user ID 1000", output)
                self.assertTrue(self.is_on(CLIENT, "active"))

    def test_the_last_assignment_counts(self):
        self.reset(TEMPLATE.replace("GHOSTLINK_OWNER_UID=\n", "GHOSTLINK_OWNER_UID=1000\nGHOSTLINK_OWNER_UID=\n"))
        output = self.run_script(POSTINST, "configure", "", sudo_uid="1001")
        self.assertNotIn("GHOSTLINK_OWNER_UID=1000", self.settings())
        self.assertIn("installed for user ID 1001", output)

    def test_an_owner_that_is_not_a_user_id_is_left_alone(self):
        settings = TEMPLATE.replace("GHOSTLINK_OWNER_UID=\n", "GHOSTLINK_OWNER_UID=alice\n")
        self.reset(settings)
        output = self.run_script(POSTINST, "configure", "", sudo_uid="1001")
        self.assertEqual(self.settings(), settings)
        self.assertFalse(self.is_on(CLIENT, "enabled") or self.is_on(CLIENT, "active"))
        self.assertIn("is not a user ID", output)

    def test_a_debian_upgrade_restarts_an_enabled_service(self):
        self.reset(OWNED, enabled=True, active=True)
        self.run_script(PRERM, "upgrade", "0.8.1")
        self.assertFalse(self.is_on(CLIENT, "active"))
        self.run_script(POSTINST, "configure", "0.8.0", sudo_uid="1001")
        self.assertTrue(self.is_on(CLIENT, "enabled") and self.is_on(CLIENT, "active"))
        self.assertEqual(self.settings(), OWNED)

    def test_an_upgrade_leaves_a_disabled_service_off(self):
        for arguments in (("configure", "0.8.0"), ("2",)):
            with self.subTest(arguments=arguments):
                self.reset(OWNED)
                output = self.run_script(POSTINST, *arguments, sudo_uid="1000")
                self.assertFalse(self.is_on(CLIENT, "enabled") or self.is_on(CLIENT, "active"))
                self.assertFalse({"enable", "start", "restart"} & set(self.calls()))
                self.assertIn("service is disabled", output)

    def test_installing_again_after_a_removal_turns_the_service_back_on(self):
        self.reset(OWNED, enabled=True, active=True)
        self.run_script(PRERM, "remove")
        self.run_script(POSTRM, "remove")
        self.assertFalse(self.is_on(CLIENT, "enabled") or self.is_on(CLIENT, "active"))
        # Debian installs from the "config-files" state with the last configured version.
        self.run_script(POSTINST, "configure", "0.8.0")
        self.assertTrue(self.is_on(CLIENT, "enabled") and self.is_on(CLIENT, "active"))
        self.assertFalse((self.root / "var/lib/ghostlink/enable-on-install").exists())

    def test_a_removal_goes_ahead_when_the_state_directory_cannot_be_written(self):
        self.reset(OWNED, enabled=True, active=True)
        (self.root / "var/lib").rmdir()
        (self.root / "var/lib").write_bytes(b"")
        self.run_script(PRERM, "remove")
        self.assertFalse(self.is_on(CLIENT, "enabled") or self.is_on(CLIENT, "active"))

    def test_installing_again_after_removing_a_disabled_service_keeps_it_off(self):
        self.reset(OWNED)
        self.run_script(PRERM, "remove")
        self.run_script(POSTRM, "remove")
        self.run_script(POSTINST, "configure", "0.8.0")
        self.assertFalse(self.is_on(CLIENT, "enabled") or self.is_on(CLIENT, "active"))

    def test_an_rpm_upgrade_leaves_the_service_running(self):
        # rpm runs the new %post, then the old %preun, then %posttrans.
        self.reset(OWNED, enabled=True, active=True)
        self.run_script(POSTINST, "2")
        self.run_script(PRERM, "1")
        self.run_script(POSTTRANS)
        self.assertTrue(self.is_on(CLIENT, "enabled") and self.is_on(CLIENT, "active"))
        self.assertNotIn("stop", self.calls())

    def test_posttrans_starts_a_service_an_older_preremove_stopped(self):
        self.reset(OWNED, enabled=True, active=True)
        self.run_script(POSTINST, "2")
        # The pre-remove of packages up to 0.8.0 stops the service when rpm passes 1.
        (self.state / f"{CLIENT}.active").unlink()
        self.run_script(POSTTRANS)
        self.assertTrue(self.is_on(CLIENT, "active"))
        self.reset(OWNED)
        self.run_script(POSTTRANS)
        self.assertFalse(self.is_on(CLIENT, "active"))

    def test_a_mesh_rpm_upgrade_leaves_the_agent_running(self):
        node = self.root / "var/lib/ghostlink-mesh/node.json"
        node.parent.mkdir(parents=True)
        node.write_bytes(b"{}")
        self.reset(OWNED, unit=MESH, enabled=True, active=True)
        self.run_script(MESH_POSTINST, "2")
        self.run_script(MESH_PRERM, "1")
        self.assertTrue(self.is_on(MESH, "active"))
        (self.state / f"{MESH}.active").unlink()
        self.run_script(MESH_POSTTRANS)
        self.assertTrue(self.is_on(MESH, "enabled") and self.is_on(MESH, "active"))


if __name__ == "__main__":
    unittest.main()
