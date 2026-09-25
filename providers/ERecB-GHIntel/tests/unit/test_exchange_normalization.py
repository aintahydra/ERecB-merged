from __future__ import annotations

from erecb_triage.ghintel.normalization import normalize_repository
from ghintel.github_urls import normalize_github_url


def test_request_repository_identities_match_ghintel():
    for source in (
        "https://github.com/Owner/Repository",
        "git@github.com:Owner/Repository.git",
        "ssh://git@github.com/Owner/Repository",
        "git://github.com/Owner/Repository.git",
    ):
        observed = normalize_repository(source)
        produced = normalize_github_url(source)
        assert observed is not None
        assert (observed.identity_key, observed.canonical_url) == (
            produced.identity_key, produced.canonical_url,
        )
