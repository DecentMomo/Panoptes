import re

from app.normalize.cwe_map import normalize_cwe
from app.normalize.owasp_map import CATEGORIES, owasp_for

_LABEL = re.compile(r"^A(0[1-9]|10):2025 - .+$")


def test_every_label_names_the_2025_edition_and_cwes_are_unique() -> None:
    seen: set[int] = set()
    for label, numbers in CATEGORIES.items():
        assert _LABEL.match(label), label
        for number in numbers:
            assert number not in seen, number
            seen.add(number)


def test_known_cwe_maps_and_unknown_stays_empty() -> None:
    assert owasp_for("CWE-78") == "A05:2025 - Injection"
    assert owasp_for("CWE-798") == "A07:2025 - Authentication Failures"
    assert owasp_for("CWE-999999") is None
    assert owasp_for(None) is None


def test_cwe_strings_normalize() -> None:
    assert normalize_cwe("CWE-78: Improper Neutralization") == "CWE-78"
    assert normalize_cwe("cwe-78") == "CWE-78"
    assert normalize_cwe(78) == "CWE-78"
    assert normalize_cwe("nope") is None


def test_semgrep_2021_metadata_is_not_the_label() -> None:
    # The fixture carries an OWASP 2021 tag. The label still comes from our table.
    assert owasp_for("CWE-78") is not None
    assert "2021" not in (owasp_for("CWE-78") or "")
    assert "Injection" in (owasp_for("CWE-78") or "")
