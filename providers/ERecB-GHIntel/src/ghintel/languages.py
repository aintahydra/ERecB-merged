"""Deterministic Unicode-script inference with a replaceable offline detector."""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from typing import Protocol

from .models import Confidence, LanguageCategory, LanguageMethod

_FENCED_CODE = re.compile(r"```.*?```", re.DOTALL)
_INDENTED_CODE = re.compile(r"^(?: {4}|\t).*$", re.MULTILINE)
_INLINE_CODE = re.compile(r"`[^`\n]*`")
_URL = re.compile(r"https?://\S+")
_SLAVIC = {"uk", "be", "bg", "mk", "sr", "pl", "cs", "sk", "sl", "hr", "bs"}
_DIRECT = {
    "zh": LanguageCategory.CHINESE,
    "ru": LanguageCategory.RUSSIAN,
    "ko": LanguageCategory.KOREAN,
    "ja": LanguageCategory.JAPANESE,
    "ar": LanguageCategory.ARABIC,
    "he": LanguageCategory.HEBREW,
    "hi": LanguageCategory.HINDI,
    "en": LanguageCategory.ENGLISH,
}


class LanguageDetector(Protocol):
    def detect(self, text: str) -> tuple[str, float] | None: ...


class LinguaDetector:
    """Lazy adapter so discovery works when Stage 2 extras are not installed."""

    def __init__(self) -> None:
        from lingua import Language, LanguageDetectorBuilder

        self._detector = LanguageDetectorBuilder.from_languages(*list(Language.all())).build()

    def detect(self, text: str) -> tuple[str, float] | None:
        result = self._detector.compute_language_confidence_values(text)
        if not result:
            return None
        language, confidence = result[0]
        return language.iso_code_639_1.name.lower(), float(confidence)


@dataclass(frozen=True, slots=True)
class LanguageInference:
    category: LanguageCategory
    method: LanguageMethod
    confidence: Confidence
    detector_language: str | None
    script_counts: dict[str, int]
    rationale: str


def clean_analysis_text(text: str) -> str:
    text = _FENCED_CODE.sub(" ", text)
    text = _INDENTED_CODE.sub(" ", text)
    text = _INLINE_CODE.sub(" ", text)
    return _URL.sub(" ", text)


def script_counts(text: str) -> dict[str, int]:
    counts = {name: 0 for name in ("hangul", "kana", "hebrew", "arabic", "devanagari", "cyrillic", "han", "latin", "other")}
    for character in text:
        if not character.isalpha():
            continue
        name = unicodedata.name(character, "")
        if "HANGUL" in name:
            counts["hangul"] += 1
        elif "HIRAGANA" in name or "KATAKANA" in name:
            counts["kana"] += 1
        elif "HEBREW" in name:
            counts["hebrew"] += 1
        elif "ARABIC" in name:
            counts["arabic"] += 1
        elif "DEVANAGARI" in name:
            counts["devanagari"] += 1
        elif "CYRILLIC" in name:
            counts["cyrillic"] += 1
        elif "CJK UNIFIED IDEOGRAPH" in name or "CJK COMPATIBILITY IDEOGRAPH" in name:
            counts["han"] += 1
        elif "LATIN" in name:
            counts["latin"] += 1
        else:
            counts["other"] += 1
    return counts


def infer_language(
    texts: list[str],
    *,
    detector: LanguageDetector | None,
    minimum_letters: int,
    minimum_script_ratio: float,
    eligible_subject: bool = True,
) -> LanguageInference:
    if not eligible_subject:
        return _unknown({}, "organization or unresolved multi-author subject")
    text = "\n".join(clean_analysis_text(item) for item in texts)
    counts = script_counts(text)
    letters = sum(counts.values())
    if letters < minimum_letters:
        return _unknown(counts, "insufficient original-source letters")
    dominant, number = max(counts.items(), key=lambda pair: pair[1])
    if number / letters < minimum_script_ratio:
        return _unknown(counts, "no script reached the configured dominance threshold")
    direct_scripts = {"hangul": LanguageCategory.KOREAN, "kana": LanguageCategory.JAPANESE, "hebrew": LanguageCategory.HEBREW}
    if dominant in direct_scripts:
        return LanguageInference(direct_scripts[dominant], LanguageMethod.UNICODE_SCRIPT, Confidence.MEDIUM, None, counts, f"dominant {dominant} script")
    detected = detector.detect(text) if detector else None
    language = detected[0] if detected else None
    category = _map_language(language)
    ambiguous_scripts = {"arabic", "devanagari", "cyrillic", "han", "latin"}
    if dominant == "latin" and category is not LanguageCategory.UNKNOWN:
        return LanguageInference(category, LanguageMethod.LANGUAGE_DETECTOR, Confidence.MEDIUM, language, counts, "Latin prose classified by offline detector")
    if dominant in ambiguous_scripts and category is not LanguageCategory.UNKNOWN:
        return LanguageInference(category, LanguageMethod.COMBINED, Confidence.MEDIUM, language, counts, f"dominant {dominant} script corroborated by detector")
    if dominant in ambiguous_scripts:
        return _unknown(counts, f"{dominant} script requires a supported detector result", language)
    return _unknown(counts, "unsupported script distribution", language)


def _map_language(language: str | None) -> LanguageCategory:
    if language in _DIRECT:
        return _DIRECT[language]
    if language in _SLAVIC:
        return LanguageCategory.SLAVIC_OTHER
    return LanguageCategory.UNKNOWN


def _unknown(counts: dict[str, int], rationale: str, detector_language: str | None = None) -> LanguageInference:
    return LanguageInference(LanguageCategory.UNKNOWN, LanguageMethod.COMBINED, Confidence.UNKNOWN, detector_language, counts, rationale)
