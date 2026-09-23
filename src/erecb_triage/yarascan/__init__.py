"""Offline, immutable-cache YARA scanning primitives."""

from .cache import CacheError, PinnedCache, pin_cache

__all__ = ["CacheError", "PinnedCache", "pin_cache"]
