"""Human-readable, capture-scoped analysis input fingerprints."""

from __future__ import annotations


def items(capture: dict, adapter: str | None = None) -> list[tuple[str, object]]:
    provenance = capture.get("analysis_provenance") or {}
    result: list[tuple[str, object]] = [("Capture generation ID", capture.get("capture_id")),
                                        ("Extraction policy SHA-256", provenance.get("policy_sha256"))]
    hashes = provenance.get("database_sha256") or {}
    if adapter is None:
        for name, digest in sorted(hashes.items()):
            result.append((f"{name} database SHA-256", digest))
    elif adapter in hashes:
        result.append(("Database SHA-256", hashes[adapter]))
    if adapter is None:
        result.append(("YARA generation pointer at run start", provenance.get("yara_generation")))
    return result
