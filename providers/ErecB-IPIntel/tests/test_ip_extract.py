from __future__ import annotations

from pathlib import Path
import unittest

from erecb_ipintel.ip_extract import canonical_ip, extract_ips_from_file, is_ignored_ip


class IPExtractTests(unittest.TestCase):
    def test_canonical_ip_validation(self) -> None:
        self.assertEqual(canonical_ip("192.0.2.1"), "192.0.2.1")
        self.assertEqual(canonical_ip("[2001:db8::1]"), "2001:db8::1")
        self.assertEqual(canonical_ip("fe80::1%eth0"), "fe80::1")
        self.assertIsNone(canonical_ip("999.1.1.1"))

    def test_ignored_ipv4_ranges(self) -> None:
        ignored = [
            "0.1.2.3",
            "10.1.2.3",
            "100.64.0.1",
            "127.0.0.1",
            "169.254.1.1",
            "172.16.0.1",
            "192.0.0.1",
            "192.0.2.1",
            "192.88.99.1",
            "192.168.1.1",
            "198.18.0.1",
            "198.51.100.1",
            "203.0.113.1",
            "224.0.0.1",
            "233.252.0.1",
            "240.0.0.1",
            "255.255.255.255",
        ]
        for ip in ignored:
            with self.subTest(ip=ip):
                self.assertTrue(is_ignored_ip(ip))
        self.assertFalse(is_ignored_ip("8.8.8.8"))

    def test_extract_ips_from_binary_chunks(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sample.bin"
            path.write_bytes(b"xx abc8.8.8.8def http://9.9.9.9/a [2001:db8::1]:443 " + b"A" * 80 + b" 1.1.1.1")
            found = extract_ips_from_file(path, chunk_size=64, overlap=80)
        self.assertNotIn("8.8.8.8", found)
        self.assertIn("9.9.9.9", found)
        self.assertIn("2001:db8::1", found)
        self.assertIn("1.1.1.1", found)

    def test_extract_ips_discards_ignored_ranges(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "ignored.bin"
            path.write_text("0.0.0.1 10.0.0.1 100.64.0.1 127.0.0.1 169.254.0.1 172.16.0.1 192.0.0.1 192.0.2.1 192.88.99.1 192.168.0.1 198.18.0.1 198.51.100.1 203.0.113.1 224.0.0.1 233.252.0.1 240.0.0.1 255.255.255.255 8.8.8.8", encoding="utf-8")
            found = extract_ips_from_file(path, chunk_size=128, overlap=80)
        self.assertEqual(found, {"8.8.8.8"})


if __name__ == "__main__":
    unittest.main()
