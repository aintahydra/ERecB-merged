from typing import Literal, TypedDict


LookupStatus = Literal["hit", "miss", "unavailable", "error"]


class GithubObservation(TypedDict):
    type: Literal["github_repository_observation"]
    identity_key: str
    canonical_url: str
    owner: str
    repository: str
    source_path: str
    display_path: str
    occurrence_count: int
    first_offset: int
    capture_name: str
    staged_capture: str
    source_event_id: str
    pipeline_run_id: str
