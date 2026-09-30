from app.services.scan_diff import diff_fingerprints


def test_diff_is_set_difference() -> None:
    fixed, new, still_open = diff_fingerprints({"a", "b", "c"}, {"b", "c", "d"})
    assert fixed == {"a"}
    assert new == {"d"}
    assert still_open == {"b", "c"}


def test_identical_scans_are_all_still_open() -> None:
    fingerprints = {"a", "b"}
    fixed, new, still_open = diff_fingerprints(fingerprints, set(fingerprints))
    assert fixed == set()
    assert new == set()
    assert still_open == fingerprints
