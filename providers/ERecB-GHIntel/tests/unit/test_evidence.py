import pytest

from ghintel.evidence import EvidenceValidationError, validate_response


def _response(quote: str, source_id: int = 1) -> str:
    return f'''{{"summary":"A test tool","tool_types":[],"capabilities":[],"intended_uses":[],"searchable_categories":[],"documented_people":[],"inferred_mother_tongue":{{"category":"English","subject_name":null,"rationale":null,"evidence":[{{"source_id":{source_id},"quote":"{quote}"}}]}}}}'''


def test_exact_evidence_is_accepted() -> None:
    response = validate_response(_response("Exact quote"), {1: "Before Exact quote after"})
    assert response.inferred_mother_tongue.category.value == "English"


@pytest.mark.parametrize("raw,sources", [(_response("invented"), {1: "different"}), (_response("anything", 2), {1: "anything"})])
def test_fabricated_or_wrong_source_evidence_is_rejected(raw: str, sources: dict[int, str]) -> None:
    with pytest.raises(EvidenceValidationError):
        validate_response(raw, sources)
