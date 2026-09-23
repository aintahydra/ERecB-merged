"""Read-only, capture-scoped access to the producer-owned IP intelligence DB."""

from __future__ import annotations

import ipaddress
import sqlite3
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path

from erecb_triage.ipintel.contracts import LookupStatus, Malicious, ProviderResult
from erecb_triage.processors.base import ProcessorError


_ENTITY_COLUMNS = (
    "id", "ip", "ip_version", "ipv4", "ipv6", "country_code", "whois", "malicious",
    "first_seen_local", "last_updated_local",
)
_CHILD_QUERIES = {
    "reverse_dns": ("ip_reverse_dns", "domain", "domain, first_seen_local"),
    "related_iocs": ("ip_related_iocs", "ioc", "ioc, first_seen_local"),
    "related_actors": ("ip_related_actors", "actor", "actor, first_seen_local"),
    "provider_results": (
        "provider_ip_results",
        ("provider_name", "provider_status", "provider_result_code", "provider_transaction_id",
         "fetched_at", "error_summary"),
        "provider_name, fetched_at DESC, id DESC",
    ),
}
_REQUIRED_COLUMNS = {
    "ip_entities": set(_ENTITY_COLUMNS),
    "ip_observations": {"id", "ip_entity_id", "source_path", "extraction_file", "observed_at"},
    "ip_reverse_dns": {"ip_entity_id", "domain", "first_seen_local"},
    "ip_related_iocs": {"ip_entity_id", "ioc", "first_seen_local"},
    "ip_related_actors": {"ip_entity_id", "actor", "first_seen_local"},
    "provider_ip_results": {
        "id", "provider_run_id", "ip_entity_id", "provider_name", "provider_status", "provider_result_code",
        "provider_transaction_id", "fetched_at", "error_summary",
    },
    "provider_runs": {
        "id", "provider_name", "started_at", "finished_at", "status", "input_file", "ip_count",
        "success_count", "failure_count",
    },
}


@dataclass(frozen=True)
class IpIntelligence:
    """Producer metadata only; current-capture paths are owned by the adapter."""

    ip_entity_id: int
    ip: str
    ip_version: int
    ipv4: str | None
    ipv6: str | None
    country_code: str | None
    whois: str | None
    malicious: Malicious
    first_seen_local: str
    last_updated_local: str
    reverse_dns: list[str]
    related_iocs: list[str]
    related_actors: list[str]
    provider_results: list[ProviderResult]


@dataclass(frozen=True)
class LookupResult:
    status: LookupStatus
    intelligence: IpIntelligence | None = None
    error: ProcessorError | None = None


class _IncompatibleSchema(Exception):
    pass


class IpIntelRepository:
    """Single-use read-only session with cache scope limited to one capture."""

    def __init__(self, db_path: Path):
        if not db_path.is_absolute():
            raise ValueError("IPIntel database path must be absolute")
        self.db_path = db_path
        self.initialization_error: ProcessorError | None = None
        self._connection: sqlite3.Connection | None = None
        self._entered = False
        self._closed = False
        self._cache: dict[str, LookupResult] = {}

    @property
    def available(self) -> bool:
        return self._connection is not None

    def __enter__(self) -> IpIntelRepository:
        if self._entered or self._closed:
            raise RuntimeError("IPIntel repository sessions are single-use")
        self._entered = True
        try:
            self._connection = sqlite3.connect(
                self.db_path.as_uri() + "?mode=ro", uri=True, isolation_level=None,
            )
            self._connection.row_factory = sqlite3.Row
            self._connection.execute("PRAGMA query_only = ON")
            self._connection.execute("PRAGMA trusted_schema = OFF")
            self._check_schema()
        except (sqlite3.Error, OSError, _IncompatibleSchema) as exc:
            code = (
                "ipintel_schema_incompatible" if isinstance(exc, _IncompatibleSchema)
                else "ipintel_db_unavailable"
            )
            self.initialization_error = ProcessorError(self.db_path, str(exc), code)
            self._close_connection()
        except BaseException:
            self.close()
            raise
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.close()

    def close(self) -> None:
        self._closed = True
        self._cache.clear()
        self._close_connection()

    def _close_connection(self) -> None:
        if self._connection is not None:
            connection, self._connection = self._connection, None
            connection.close()

    def _check_schema(self) -> None:
        assert self._connection is not None
        for table, required in _REQUIRED_COLUMNS.items():
            row = self._connection.execute(
                "SELECT type FROM sqlite_schema WHERE name = ?", (table,),
            ).fetchone()
            if row is None or row["type"] != "table":
                raise _IncompatibleSchema(f"Missing lookup table: {table}")
            columns = {
                row["name"] for row in self._connection.execute(f'PRAGMA table_info("{table}")')
            }
            missing = required - columns
            if missing:
                raise _IncompatibleSchema(
                    f"Missing columns in {table}: {', '.join(sorted(missing))}"
                )

    def lookup(self, ip: str) -> LookupResult:
        """Retrieve one already-canonical IP and all required child metadata."""
        if not self._entered or self._closed:
            raise RuntimeError("Lookup requires an active IPIntel repository context")
        canonical = _canonical_ip(ip)
        if canonical in self._cache:
            return deepcopy(self._cache[canonical])
        if self.initialization_error is not None:
            result = LookupResult("unavailable", error=self.initialization_error)
        else:
            assert self._connection is not None
            try:
                # Keep parent and child metadata coherent without retaining a capture-wide read lock.
                self._connection.execute("BEGIN")
                try:
                    result = self._lookup(canonical)
                finally:
                    self._connection.rollback()
            except sqlite3.Error as exc:
                result = LookupResult("error", error=ProcessorError(
                    self.db_path, str(exc), "ipintel_lookup_error",
                ))
        self._cache[canonical] = result
        return deepcopy(result)

    def _lookup(self, ip: str) -> LookupResult:
        assert self._connection is not None
        rows = self._connection.execute(
            f"SELECT {', '.join(_ENTITY_COLUMNS)} FROM ip_entities WHERE ip = ? ORDER BY id", (ip,),
        ).fetchall()
        if not rows:
            return LookupResult("miss")
        if len(rows) != 1:
            raise sqlite3.DatabaseError("Multiple IP entities have the same canonical IP")
        row = rows[0]
        parsed = ipaddress.ip_address(ip)
        if row["ip_version"] != parsed.version:
            raise sqlite3.DatabaseError("IP entity version does not match its canonical IP")
        if row["ip"] != ip:
            raise sqlite3.DatabaseError("IP entity key does not match its canonical IP")
        if row["malicious"] not in ("Yes", "No", None):
            raise sqlite3.DatabaseError("IP entity has an invalid malicious verdict")
        entity_id = row["id"]
        children: dict[str, list] = {}
        for name, query in _CHILD_QUERIES.items():
            table, columns, ordering = query
            if isinstance(columns, str):
                children[name] = [
                    child[columns] for child in self._connection.execute(
                        f"SELECT {columns} FROM {table} WHERE ip_entity_id = ? ORDER BY {ordering}",
                        (entity_id,),
                    )
                ]
            else:
                children[name] = [dict(child) for child in self._connection.execute(
                    f"SELECT {', '.join(columns)} FROM {table} WHERE ip_entity_id = ? ORDER BY {ordering}",
                    (entity_id,),
                )]
        for provider in children["provider_results"]:
            if provider["provider_status"] not in {"success", "not_found", "failed"}:
                raise sqlite3.DatabaseError("Provider result has an invalid status")
        return LookupResult("hit", intelligence=IpIntelligence(
            ip_entity_id=entity_id,
            ip=row["ip"],
            ip_version=row["ip_version"],
            ipv4=row["ipv4"],
            ipv6=row["ipv6"],
            country_code=row["country_code"],
            whois=row["whois"],
            malicious=row["malicious"],
            first_seen_local=row["first_seen_local"],
            last_updated_local=row["last_updated_local"],
            reverse_dns=children["reverse_dns"],
            related_iocs=children["related_iocs"],
            related_actors=children["related_actors"],
            provider_results=children["provider_results"],
        ))


def _canonical_ip(value: str) -> str:
    if not isinstance(value, str) or "%" in value:
        raise ValueError("IP lookup key must be a canonical IPv4 or IPv6 string")
    try:
        parsed = ipaddress.ip_address(value)
    except ValueError as exc:
        raise ValueError("IP lookup key must be a canonical IPv4 or IPv6 string") from exc
    if str(parsed) != value:
        raise ValueError("IP lookup key must be canonical")
    return value
