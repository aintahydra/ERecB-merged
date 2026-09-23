from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from erecb_ipintel.config import CtxIoConfig
from erecb_ipintel.models import ProviderRawResult
from erecb_ipintel.providers.ctx_io import CtxIoProvider


class CtxIoTests(unittest.TestCase):
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
