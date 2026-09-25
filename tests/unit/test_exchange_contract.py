from __future__ import annotations

import hashlib
import tempfile
import unittest
import uuid
from pathlib import Path

from erecb_triage.exchange import BundleError, new_bundle, read_bundle, validate_bundle, write_bundle


class ExchangeContractTests(unittest.TestCase):
    def bundle(self):
        return new_bundle(
            source_instance_id=str(uuid.uuid4()), source_sequence=1,
            selection="missing", policy_sha256="0" * 64,
            files=[{"sha256": "a" * 64, "md5": "b" * 32}],
            ips=["2001:db8::1", "8.8.8.8"],
            repositories=[{"identity_key": "github.com/example/tool",
                           "canonical_url": "https://github.com/Example/Tool"}],
        )

    def test_bundle_round_trip_and_checksum(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "requests.json"
            original = self.bundle()
            write_bundle(path, original)
            self.assertEqual(read_bundle(path), original)
            self.assertNotIn("source_path", path.read_text(encoding="ascii"))
            with self.assertRaises(BundleError):
                write_bundle(path, original)
            path.write_bytes(path.read_bytes().replace(b"8.8.8.8", b"9.9.9.9"))
            with self.assertRaisesRegex(BundleError, "checksum"):
                read_bundle(path)

    def test_rejects_extra_fields_and_conflicting_identity(self):
        value = self.bundle()
        value["source_path"] = "/captured/private"
        with self.assertRaises(BundleError):
            validate_bundle(value)
        del value["source_path"]
        value["repositories"][0]["identity_key"] = "github.com/other/tool"
        with self.assertRaises(BundleError):
            validate_bundle(value)

    def test_rejects_duplicate_json_keys_even_with_matching_checksum(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "requests.json"
            write_bundle(path, self.bundle())
            payload = path.read_text(encoding="ascii")
            payload = payload.replace('"schema_version":1', '"schema_version":1,"schema_version":1')
            self.assertNotEqual(payload, path.read_text(encoding="ascii"))
            path.write_text(payload, encoding="ascii")
            Path(str(path) + ".sha256").write_text(
                hashlib.sha256(payload.encode("ascii")).hexdigest() + "  requests.json\n",
                encoding="ascii",
            )
            with self.assertRaisesRegex(BundleError, "duplicate JSON key"):
                read_bundle(path)


if __name__ == "__main__":
    unittest.main()
