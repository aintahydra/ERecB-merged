from ghintel.languages import infer_language
from ghintel.models import LanguageCategory, LanguageMethod

import pytest


class Detector:
    def __init__(self, code: str):
        self.code = code

    def detect(self, text: str):
        return self.code, 0.99


def test_kana_beats_han_for_japanese() -> None:
    result = infer_language(["これは日本語の文章です。" * 20], detector=None, minimum_letters=20, minimum_script_ratio=0.2)
    assert result.category is LanguageCategory.JAPANESE


def test_cyrillic_requires_detector_and_maps_ukrainian() -> None:
    text = "Це український текст для перевірки класифікації. " * 10
    result = infer_language([text], detector=Detector("uk"), minimum_letters=20, minimum_script_ratio=0.2)
    assert result.category is LanguageCategory.SLAVIC_OTHER


def test_unsupported_latin_language_is_unknown() -> None:
    result = infer_language(["Este es un texto español suficientemente largo para la prueba. " * 10], detector=Detector("es"), minimum_letters=20, minimum_script_ratio=0.2)
    assert result.category is LanguageCategory.UNKNOWN


def test_code_blocks_do_not_supply_script_signal() -> None:
    result = infer_language(["```\n한국어 텍스트\n```" * 20], detector=None, minimum_letters=1, minimum_script_ratio=0.2)
    assert result.category is LanguageCategory.UNKNOWN


@pytest.mark.parametrize(
    ("text", "detector_code", "expected"),
    [
        ("한국어 문서의 설명입니다. 사용 방법을 안내합니다. " * 10, None, LanguageCategory.KOREAN),
        ("这是项目的中文说明，包含使用方法和功能介绍。 " * 10, "zh", LanguageCategory.CHINESE),
        ("هذا وصف عربي للمشروع ويشرح الاستخدام والوظائف. " * 10, "ar", LanguageCategory.ARABIC),
        ("זהו תיאור בעברית של הפרויקט ושל יכולותיו. " * 10, None, LanguageCategory.HEBREW),
        ("यह परियोजना का हिंदी विवरण है और उपयोग समझाता है। " * 10, "hi", LanguageCategory.HINDI),
        ("Это русское описание проекта и его возможностей. " * 10, "ru", LanguageCategory.RUSSIAN),
        ("Това е българско описание на проекта и функциите му. " * 10, "bg", LanguageCategory.SLAVIC_OTHER),
        ("To jest polski opis projektu i jego możliwości. " * 10, "pl", LanguageCategory.SLAVIC_OTHER),
        ("Toto je český popis projektu a jeho funkcí. " * 10, "cs", LanguageCategory.SLAVIC_OTHER),
        ("این توضیح فارسی پروژه و قابلیت‌های آن است. " * 10, "fa", LanguageCategory.UNKNOWN),
        ("یہ منصوبے اور اس کی خصوصیات کی اردو وضاحت ہے۔ " * 10, "ur", LanguageCategory.UNKNOWN),
        ("Ceci est une description française du projet et de ses fonctions. " * 10, "fr", LanguageCategory.UNKNOWN),
        ("This is a sufficiently long English project description with documented capabilities. " * 10, "en", LanguageCategory.ENGLISH),
    ],
)
def test_language_script_fixtures(text: str, detector_code: str | None, expected: LanguageCategory) -> None:
    result = infer_language([text], detector=Detector(detector_code) if detector_code else None, minimum_letters=20, minimum_script_ratio=0.2)
    assert result.category is expected


def test_latin_result_is_marked_as_language_detector() -> None:
    result = infer_language(["English original project prose. " * 20], detector=Detector("en"), minimum_letters=20, minimum_script_ratio=0.2)
    assert result.method is LanguageMethod.LANGUAGE_DETECTOR


def test_code_noise_does_not_remove_following_original_prose() -> None:
    text = "```\n한국어 텍스트\n```\n" + ("This English project documentation describes its capabilities. " * 10)
    result = infer_language([text], detector=Detector("en"), minimum_letters=20, minimum_script_ratio=0.2)
    assert result.category is LanguageCategory.ENGLISH
    assert result.script_counts["hangul"] == 0


def test_insufficient_text_and_ineligible_subject_are_unknown() -> None:
    short = infer_language(["English"], detector=Detector("en"), minimum_letters=20, minimum_script_ratio=0.2)
    organization = infer_language(["English prose. " * 20], detector=Detector("en"), minimum_letters=20, minimum_script_ratio=0.2, eligible_subject=False)
    assert short.category is LanguageCategory.UNKNOWN
    assert organization.category is LanguageCategory.UNKNOWN
