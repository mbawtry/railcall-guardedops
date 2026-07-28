"""Sign or verify a RailCall module bundle without exposing publisher secrets."""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import tempfile

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


def _manifest_bytes(manifest):
    canonical = dict(manifest)
    canonical.pop("signature", None)
    return json.dumps(
        canonical, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _signed_bytes(manifest, handler_bytes):
    return _manifest_bytes(manifest) + b"\n" + handler_bytes


def _read_bundle(module_dir):
    manifest_path = module_dir / "module.json"
    handler_path = module_dir / "handlers" / "handler.py"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        handler_bytes = handler_path.read_bytes()
    except (OSError, ValueError) as exc:
        raise RuntimeError(f"cannot read module bundle: {exc}") from exc
    if not isinstance(manifest, dict):
        raise RuntimeError("module.json must contain a JSON object")
    return manifest, handler_bytes


def _raw_public_key(private_key):
    return private_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )


def _load_publisher_record(path):
    try:
        record = json.loads(path.read_text(encoding="utf-8"))
        seed = bytes.fromhex(record["seed_hex"])
        public = bytes.fromhex(record["pubkey_hex"])
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise RuntimeError(f"publisher record is invalid: {exc}") from exc
    if len(seed) != 32 or len(public) != 32:
        raise RuntimeError("publisher seed and public key must each be 32 bytes")
    private_key = Ed25519PrivateKey.from_private_bytes(seed)
    if _raw_public_key(private_key) != public:
        raise RuntimeError("publisher seed does not derive the stored public key")
    return private_key, public


def _atomic_write_text(path, content):
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=path.name + ".", suffix=".tmp", dir=str(path.parent)
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(content)
        os.replace(temporary_name, path)
    except BaseException:
        try:
            os.unlink(temporary_name)
        except OSError:
            pass
        raise


def sign_bundle(module_dir, publisher_record):
    manifest, handler_bytes = _read_bundle(module_dir)
    private_key, public = _load_publisher_record(publisher_record)
    manifest["publisher_pubkey"] = public.hex()
    signature = private_key.sign(_signed_bytes(manifest, handler_bytes)).hex()

    manifest_text = json.dumps(manifest, indent=2, ensure_ascii=False) + "\n"
    _atomic_write_text(module_dir / "module.json", manifest_text)
    _atomic_write_text(module_dir / "module.sig", signature + "\n")
    return public.hex()


def verify_bundle(module_dir):
    manifest, handler_bytes = _read_bundle(module_dir)
    try:
        public = bytes.fromhex(manifest["publisher_pubkey"])
        signature = bytes.fromhex(
            (module_dir / "module.sig").read_text(encoding="utf-8").strip()
        )
        Ed25519PublicKey.from_public_bytes(public).verify(
            signature, _signed_bytes(manifest, handler_bytes)
        )
    except (OSError, ValueError, KeyError, InvalidSignature) as exc:
        raise RuntimeError(f"module signature is invalid: {exc}") from exc
    return public.hex()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("module_dir", type=pathlib.Path)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        "--publisher-record",
        type=pathlib.Path,
        help="RailCall marketplace_publisher.json; used only for signing",
    )
    mode.add_argument("--check", action="store_true", help="verify the existing signature")
    args = parser.parse_args(argv)

    module_dir = args.module_dir.resolve()
    try:
        if args.check:
            public = verify_bundle(module_dir)
            action = "verified"
        else:
            public = sign_bundle(module_dir, args.publisher_record.resolve())
            action = "signed and verified"
            verify_bundle(module_dir)
    except RuntimeError as exc:
        parser.error(str(exc))
    print(f"{action}; publisher key fingerprint {public[:16]}...")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
