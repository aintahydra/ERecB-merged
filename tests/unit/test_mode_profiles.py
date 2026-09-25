from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

from erecb_triage.mode import ModeError, require_mode


ROOT = Path(__file__).parents[2]
for provider in ("ERecB-FileIntel", "ErecB-IPIntel"):
    sys.path.insert(0, str(ROOT / "providers" / provider / "src"))


class ModeProfileTests(unittest.TestCase):
    def test_selected_profiles_enforce_connected_and_airgap_roles(self):
        require_mode("connected", ROOT / "config/connected.yaml")
        require_mode("airgap", ROOT / "config/airgap.yaml")
        with self.assertRaisesRegex(ModeError, "requires the connected profile"):
            require_mode("connected", ROOT / "config/airgap.yaml")
        with self.assertRaisesRegex(ModeError, "requires the airgap profile"):
            require_mode("airgap", ROOT / "config/connected.yaml")

    def test_role_is_required_and_can_come_from_environment(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(ModeError, "select a machine role"):
                require_mode("connected")
        with patch.dict(os.environ, {"ERECB_MODE_PROFILE": str(ROOT / "config/connected.yaml")}):
            require_mode("connected")

    def test_ip_and_file_cli_reject_wrong_role_before_reading_bundle_or_config(self):
        from erecb_fileintel.cli import main as file_main
        from erecb_ipintel.cli import main as ip_main

        profile = str(ROOT / "config/airgap.yaml")
        missing_bundle = ROOT / "does-not-exist.json"
        self.assertEqual(file_main(["requests", "import", str(missing_bundle), "--mode-profile", profile]), 2)
        self.assertEqual(ip_main(["requests", "import", str(missing_bundle), "--mode-profile", profile]), 2)
        self.assertEqual(file_main(["merge-db", "--source", "absent", "--dest", "absent",
                                    "--mode-profile", str(ROOT / "config/connected.yaml")]), 2)
        self.assertEqual(ip_main(["merge-db", "--source", "absent", "--dest", "absent",
                                  "--mode-profile", str(ROOT / "config/connected.yaml")]), 2)

    def test_ip_cli_handles_non_mode_errors_without_crashing(self):
        from erecb_ipintel.cli import main as ip_main

        self.assertEqual(ip_main(["db", "verify", "--source", str(ROOT / "absent-snapshot.sqlite3")]), 1)


if __name__ == "__main__":
    unittest.main()
