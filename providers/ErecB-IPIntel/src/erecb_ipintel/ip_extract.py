from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable
from pathlib import Path


TOKEN_RE = re.compile(rb"[A-Za-z0-9_.:%-]+")
IPV4_RE = re.compile(rb"(?<![A-Za-z0-9_])(?:\d{1,3}\.){3}\d{1,3}(?![A-Za-z0-9_])")
TRIM_CHARS = " \t\r\n()[]{}<>,;'\""
IGNORED_IPV4_NETWORKS: tuple[ipaddress.IPv4Network, ...] = (
    ipaddress.IPv4Network("0.0.0.0/8"),
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("100.64.0.0/10"),
    ipaddress.IPv4Network("127.0.0.0/8"),
    ipaddress.IPv4Network("169.254.0.0/16"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.0.0.0/24"),
    ipaddress.IPv4Network("192.0.2.0/24"),
    ipaddress.IPv4Network("192.88.99.0/24"),
    ipaddress.IPv4Network("192.168.0.0/16"),
    ipaddress.IPv4Network("198.18.0.0/15"),
    ipaddress.IPv4Network("198.51.100.0/24"),
    ipaddress.IPv4Network("203.0.113.0/24"),
    ipaddress.IPv4Network("224.0.0.0/4"),
    ipaddress.IPv4Network("233.252.0.0/24"),
    ipaddress.IPv4Network("240.0.0.0/4"),
    ipaddress.IPv4Network("255.255.255.255/32"),
)


def canonical_ip(value: str) -> str | None:
    text = _strip_candidate(value)
    if "%" in text:
        left, zone = text.split("%", 1)
        if zone and all(ch.isalnum() or ch in "._-" for ch in zone):
            text = left
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return None


def is_ignored_ip(value: str) -> bool:
    try:
        parsed = ipaddress.ip_address(value)
    except ValueError:
        return False
    if not isinstance(parsed, ipaddress.IPv4Address):
        return False
    return any(parsed in network for network in IGNORED_IPV4_NETWORKS)


def extract_ips_from_file(path: Path, chunk_size: int, overlap: int) -> set[str]:
    found: set[str] = set()
    tail = b""
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(chunk_size)
            if not chunk:
                break
            data = tail + chunk
            for candidate in _candidate_strings(data, skip_leading_partial=bool(tail)):
                ip = canonical_ip(candidate)
                if ip is not None and not is_ignored_ip(ip):
                    found.add(ip)
            tail = data[-overlap:] if overlap else b""
    return found


def _candidate_strings(data: bytes, skip_leading_partial: bool = False) -> Iterable[str]:
    yielded: set[str] = set()
    for match in TOKEN_RE.finditer(data):
        if skip_leading_partial and match.start() == 0:
            continue
        token = match.group(0).decode("ascii", errors="ignore")
        if not token:
            continue
        if ":" in token:
            # Strip common URL prefixes without treating arbitrary words as IPv6.
            token = token.removeprefix("http://").removeprefix("https://")
            token = token.split("/", 1)[0]
            for candidate in _ipv6_candidates(token):
                if candidate not in yielded:
                    yielded.add(candidate)
                    yield candidate
        for ipv4 in IPV4_RE.finditer(match.group(0)):
            candidate = ipv4.group(0).decode("ascii")
            if candidate not in yielded:
                yielded.add(candidate)
                yield candidate


def _ipv6_candidates(token: str) -> Iterable[str]:
    cleaned = _strip_candidate(token)
    if cleaned.startswith("[") and "]" in cleaned:
        yield cleaned[1 : cleaned.index("]")]
        return
    if cleaned.count(":") >= 2:
        yield cleaned


def _strip_candidate(value: str) -> str:
    text = value.strip(TRIM_CHARS)
    if text.startswith("[") and "]" in text:
        text = text[1 : text.index("]")]
    return text.strip(TRIM_CHARS)
