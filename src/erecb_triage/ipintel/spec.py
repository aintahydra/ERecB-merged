"""Frozen Phase 1 extraction decisions consumed by the future streaming extractor."""


MIN_CHUNK_OVERLAP_BYTES = 128
MAX_IP_TOKEN_BYTES = 110
IPINTEL_METRIC_KEYS = (
    "ipintel_files_scanned", "ipintel_files_skipped", "ipintel_observations",
    "ipintel_unique_ips", "ipintel_lookup_hits", "ipintel_lookup_misses",
    "ipintel_lookup_unavailable", "ipintel_lookup_errors",
)

# Mapped IPv6 remains an IPv6 lookup key. These ranges apply only to version-four values.
IGNORED_IPV4_NETWORKS = (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
    "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
    "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24",
    "203.0.113.0/24", "224.0.0.0/4", "233.252.0.0/24", "240.0.0.0/4",
    "255.255.255.255/32",
)
