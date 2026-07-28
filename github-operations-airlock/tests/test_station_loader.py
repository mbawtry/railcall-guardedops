"""Optional clean-workspace integration test against a stock RailCall station."""

import importlib.util
import json
import os
import pathlib
import shutil
import sys
import tempfile
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


ROOT = pathlib.Path(__file__).resolve().parents[1]
SIGNER_PATH = ROOT / "tools" / "sign_module.py"
STATION_WORKBENCH = os.environ.get("RAILCALL_STATION_WORKBENCH")


def load_file(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@unittest.skipUnless(
    STATION_WORKBENCH,
    "set RAILCALL_STATION_WORKBENCH to run the stock-station loader test",
)
class StockStationTests(unittest.TestCase):
    def test_fresh_station_loads_all_commands_and_runs_a_real_read(self):
        workbench = pathlib.Path(STATION_WORKBENCH).resolve()
        self.assertTrue((workbench / "studio_server.py").is_file())
        sys.path.insert(0, str(workbench))
        try:
            station = load_file(
                "railcall_stock_station_for_module_test",
                workbench / "studio_server.py",
            )
        finally:
            sys.path.pop(0)

        signer = load_file("railcall_bundle_signer_for_station_test", SIGNER_PATH)
        with tempfile.TemporaryDirectory() as temporary:
            sandbox = pathlib.Path(temporary)
            module_dir = sandbox / "modules" / "github-operations"
            (module_dir / "handlers").mkdir(parents=True)
            shutil.copy2(ROOT / "module.json", module_dir / "module.json")
            shutil.copy2(
                ROOT / "handlers" / "handler.py",
                module_dir / "handlers" / "handler.py",
            )

            private = Ed25519PrivateKey.generate()
            seed = private.private_bytes(
                serialization.Encoding.Raw,
                serialization.PrivateFormat.Raw,
                serialization.NoEncryption(),
            )
            public = private.public_key().public_bytes(
                serialization.Encoding.Raw,
                serialization.PublicFormat.Raw,
            )
            publisher_record = sandbox / "publisher.json"
            publisher_record.write_text(
                json.dumps(
                    {"seed_hex": seed.hex(), "pubkey_hex": public.hex()}
                ),
                encoding="utf-8",
            )
            signer.sign_bundle(module_dir, publisher_record)

            station._MODULES_DIR = str(sandbox / "modules")
            station.WS = str(sandbox / "workspace")
            state = station._load_modules()
            self.assertEqual([], state["rejected"])
            self.assertEqual(1, len(state["loaded"]))
            self.assertEqual(31, len(state["loaded"][0]["commands"]))

            handler = station.LOCAL_HANDLERS["github.get_repository"]
            result, artifact = handler(
                {"owner": "octocat", "repo": "Hello-World"}, {}
            )
            self.assertIsNone(artifact)
            self.assertEqual(
                "octocat/Hello-World", result["repository"]["full_name"]
            )


if __name__ == "__main__":
    unittest.main()
