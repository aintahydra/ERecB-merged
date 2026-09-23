import pytest

from ghintel.github_urls import normalize_github_url


@pytest.mark.parametrize(
    "url",
    [
        "https://github.com/Owner/Repository.git",
        "http://github.com/Owner/Repository/",
        "git://github.com/Owner/Repository.git",
        "ssh://git@github.com/Owner/Repository.git",
        "git@github.com:Owner/Repository.git",
    ],
)
def test_supported_urls_normalize_to_one_identity(url: str) -> None:
    repository = normalize_github_url(url)
    assert repository.identity_key == "github.com/owner/repository"
    assert repository.canonical_url == "https://github.com/Owner/Repository"


@pytest.mark.parametrize(
    "url",
    [
        "https://token@github.com/Owner/Repository",
        "https://github.com/Owner/Repository?x=1",
        "https://example.com/Owner/Repository",
        "https://github.com/Owner/Repository/extra",
        "git@github.com:Owner",
    ],
)
def test_unsupported_urls_are_rejected(url: str) -> None:
    with pytest.raises(ValueError):
        normalize_github_url(url)
