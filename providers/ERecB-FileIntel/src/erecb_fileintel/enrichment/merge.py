from __future__ import annotations


MALICIOUS_RANK = {"unknown": 0, "no": 1, "yes": 2}


def merge_malicious(current: str | None, incoming: str | None) -> str:
    current_value = current or "unknown"
    incoming_value = incoming or "unknown"
    if MALICIOUS_RANK[incoming_value] > MALICIOUS_RANK[current_value]:
        return incoming_value
    return current_value


def normalize_hash(value: str | None) -> str | None:
    if value is None:
        return None
    cleaned = value.strip().lower()
    return None if cleaned in {"", "none"} else cleaned


def unique_clean(values: tuple[str, ...] | list[str]) -> tuple[str, ...]:
    seen: set[str] = set()
    cleaned: list[str] = []
    for value in values:
        item = str(value).strip()
        if item and item not in seen:
            seen.add(item)
            cleaned.append(item)
    return tuple(cleaned)
