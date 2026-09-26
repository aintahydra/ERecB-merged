from __future__ import annotations

import argparse
import uuid
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from erecb_ipintel.config import CtxIoConfig, load_config
from erecb_ipintel.cli import run_homework_command
from erecb_ipintel.models import ProviderRawResult
from erecb_ipintel.providers.ctx_io import CtxIoProvider
from erecb_ipintel.providers.base import CredentialError
from erecb_triage.exchange import new_bundle, write_bundle
from erecb_triage.homework import HomeworkQueue


class CtxIoTests(unittest.TestCase):
    def test_homework_run_checks_credentials_before_leasing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, patch.dict("os.environ", {"CTX_IO_API_KEY": ""}):
            root = Path(tmp)
            config = load_config(root=root)
            bundle_path = root / "requests.json"
            write_bundle(bundle_path, new_bundle(
                source_instance_id=str(uuid.uuid4()), source_sequence=1, selection="missing",
                policy_sha256="0" * 64, files=[], ips=["8.8.8.8"], repositories=[],
            ))
            state_path = config.paths.db_path.with_name("ipintel-homework.sqlite3")
            with HomeworkQueue(state_path, "ip") as queue:
                queue.import_bundle(bundle_path)
            args = argparse.Namespace(command="homework", action="run", state=None, limit=20)
            with self.assertRaisesRegex(CredentialError, "CTX.IO API key is not configured"):
                run_homework_command(args, config)
            with HomeworkQueue(state_path, "ip") as queue:
                item = queue.list_items()[0]
                self.assertEqual(item["status"], "pending")
                self.assertEqual(item["attempts"], 0)

    def test_missing_key_is_detected_before_provider_work(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, patch.dict("os.environ", {"CTX_IO_API_KEY": ""}):
            provider = CtxIoProvider(CtxIoConfig(), Path(tmp))
            with self.assertRaisesRegex(CredentialError, "CTX.IO API key is not configured"):
                provider.validate_credentials()

    def test_ctx_io_normalization(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            provider = CtxIoProvider(CtxIoConfig(api_key="fake"), Path(tmp))
            raw = ProviderRawResult(
                status="success",
                status_code=200,
                data={
                    "request": {"ctx_transaction_id": "tx-1"},
                    "ctx_result": {"result_code": 200},
                    "ctx_data": {
                        "ipv4": "156.236.72.121",
                        "detect": "malicious",
                        "country_code": "SC",
                        "whois": "inetnum: example",
                        "reverse_dns": ["z.example.com"],
                        "apt_ioc_indicator": {
                            "files": ["A" * 64],
                            "domains": ["yhyhzx.com"],
                            "ips": ["156.232.139.135"],
                            "urls": ["https://junkao360.com/"],
                        },
                        "apt_threat_actors": [
                            {"name": "Barium", "aliases": ["Wicked Spider"], "country_code": "cn"}
                        ],
                    },
                },
            )
            normalized = provider.normalize("156.236.72.121", raw)
        self.assertEqual(normalized.malicious, "Yes")
        self.assertEqual(normalized.related_iocs, ["A" * 64, "yhyhzx.com", "156.232.139.135", "https://junkao360.com/"])
        self.assertEqual(normalized.related_actors, ["(CN)Barium/Wicked Spider"])
        self.assertEqual(normalized.provider_transaction_id, "tx-1")


if __name__ == "__main__":
    unittest.main()
