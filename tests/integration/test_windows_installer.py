"""Who owns the Windows service after a first install and after an upgrade.

An install test in CI does not reach this, so it is checked with a small model of how Windows
Installer fills GHOSTLINK_OWNER_SID from packages/windows/Ghostlink.wxs.
"""
from pathlib import Path
import re
import unittest
from xml.etree import ElementTree

ROOT = Path(__file__).resolve().parents[2]
WIX = "{http://schemas.microsoft.com/wix/2006/wi}"


class WindowsInstallerOwner(unittest.TestCase):
    """GHOSTLINK_OWNER_SID across the install sequences.

    The model follows Windows Installer: AppSearch sets the property when the previous
    installation saved an owner in the registry, over a value given on the command line. AppSearch
    and Sequence="first" assignments run only in the first sequence: the UI sequence, or the
    execute sequence when the UI is skipped (msiexec /qn). Only public (upper-case) properties
    reach the execute sequence after the UI sequence.
    """

    USER = "S-1-5-21-1000-1000-1000-1001"
    SAVED = "S-1-5-21-1000-1000-1000-1002"
    GIVEN = "S-1-5-21-1000-1000-1000-1003"

    @classmethod
    def setUpClass(cls):
        cls.product = ElementTree.parse(ROOT / "packages/windows/Ghostlink.wxs").getroot().find(WIX + "Product")
        standard = {"AppSearch": 50, "LaunchConditions": 100}
        cls.actions = [(standard["AppSearch"], None)]
        for element in cls.product.iter(WIX + "SetProperty"):
            anchor = element.get("Before") or element.get("After")
            cls.actions.append((standard[anchor] + (-1 if element.get("Before") else 1), element))
        cls.actions.sort(key=lambda action: action[0])

    @staticmethod
    def holds(condition, properties):
        condition = (condition or "").strip()
        if not condition:
            return True
        if condition.startswith("NOT "):
            return not properties.get(condition[4:].strip())
        if re.fullmatch(r"\w+", condition):
            return bool(properties.get(condition))
        raise AssertionError(f"the model does not handle the condition {condition!r}")

    def owner(self, given=None, saved=None, interactive=True):
        properties = {"UserSID": self.USER}
        if given:
            properties["GHOSTLINK_OWNER_SID"] = given
        sequences = ["ui", "execute"] if interactive else ["execute"]
        for sequence in sequences:
            if sequence != sequences[0]:
                properties = {name: value for name, value in properties.items() if name.isupper() or name == "UserSID"}
            for _, element in self.actions:
                scheduled = "first" if element is None else element.get("Sequence", "both")
                if (scheduled == "first" and sequence != sequences[0]) or scheduled not in ("first", "both", sequence):
                    continue
                if element is None:
                    if saved:
                        properties["GHOSTLINK_OWNER_SID"] = saved
                elif self.holds(element.text, properties):
                    value = re.sub(r"\[(\w+)\]", lambda match: properties.get(match.group(1), ""), element.get("Value"))
                    if value:
                        properties[element.get("Id")] = value
                    else:
                        properties.pop(element.get("Id"), None)
        return properties.get("GHOSTLINK_OWNER_SID")

    def test_a_first_install_belongs_to_the_installing_user_or_the_given_sid(self):
        for interactive in (True, False):
            with self.subTest(interactive=interactive):
                self.assertEqual(self.owner(interactive=interactive), self.USER)
                self.assertEqual(self.owner(given=self.GIVEN, interactive=interactive), self.GIVEN)

    def test_an_upgrade_keeps_the_saved_owner(self):
        for interactive in (True, False):
            with self.subTest(interactive=interactive):
                self.assertEqual(self.owner(saved=self.SAVED, interactive=interactive), self.SAVED)

    def test_an_upgrade_with_a_given_sid_changes_the_owner(self):
        for interactive in (True, False):
            with self.subTest(interactive=interactive):
                self.assertEqual(self.owner(given=self.GIVEN, saved=self.SAVED, interactive=interactive), self.GIVEN)

    def test_the_service_and_the_saved_owner_use_the_property(self):
        service = self.product.find(f".//{WIX}ServiceInstall")
        self.assertIn('--owner-sid "[GHOSTLINK_OWNER_SID]"', service.get("Arguments"))
        saved = [value for value in self.product.iter(WIX + "RegistryValue") if value.get("Name") == "OwnerSID"]
        self.assertEqual([value.get("Value") for value in saved], ["[GHOSTLINK_OWNER_SID]"])


if __name__ == "__main__":
    unittest.main()
