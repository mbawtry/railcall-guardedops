import importlib.util
import json
import pathlib
import tempfile
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


ROOT = pathlib.Path(__file__).resolve().parents[1]
SIGNER_PATH = ROOT / "tools" / "sign_module.py"


def load_signer():
    spec = importlib.util.spec_from_file_location("railcall_module_signer", SIGNER_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ModuleSigningTests(unittest.TestCase):
    def setUp(self):
        self.signer = load_signer()

    def test_sign_verify_and_tamper_detection(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            (root / "handlers").mkdir()
            (root / "module.json").write_text(
                json.dumps({"id": "test/example", "version": "1.0.0"}),
                encoding="utf-8",
            )
            (root / "handlers" / "handler.py").write_text(
                "def test(inputs, stamp):\n    return {'ok': True}, None\n",
                encoding="utf-8",
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
            record_path = root / "publisher.json"
            record_path.write_text(
                json.dumps(
                    {
                        "alg": "ed25519",
                        "seed_hex": seed.hex(),
                        "pubkey_hex": public.hex(),
                    }
                ),
                encoding="utf-8",
            )

            self.assertEqual(
                public.hex(), self.signer.sign_bundle(root, record_path)
            )
            self.assertEqual(public.hex(), self.signer.verify_bundle(root))

            handler_path = root / "handlers" / "handler.py"
            handler_path.write_text(
                handler_path.read_text(encoding="utf-8") + "# tampered\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(RuntimeError, "signature is invalid"):
                self.signer.verify_bundle(root)

    def test_mismatched_publisher_record_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            (root / "handlers").mkdir()
            (root / "module.json").write_text("{}", encoding="utf-8")
            (root / "handlers" / "handler.py").write_text("", encoding="utf-8")
            first = Ed25519PrivateKey.generate()
            second = Ed25519PrivateKey.generate()
            seed = first.private_bytes(
                serialization.Encoding.Raw,
                serialization.PrivateFormat.Raw,
                serialization.NoEncryption(),
            )
            public = second.public_key().public_bytes(
                serialization.Encoding.Raw,
                serialization.PublicFormat.Raw,
            )
            record_path = root / "publisher.json"
            record_path.write_text(
                json.dumps(
                    {"seed_hex": seed.hex(), "pubkey_hex": public.hex()}
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(RuntimeError, "does not derive"):
                self.signer.sign_bundle(root, record_path)


if __name__ == "__main__":
    unittest.main()
