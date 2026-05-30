"""Field validators that the promotion/report gates depend on."""


def test_substantive_rejects_placeholders(h):
    for bad in (None, "", "unchecked", [], "x", "TODO", "tbd", "n/a"):
        assert h.substantive(bad) is False


def test_substantive_accepts_real_text(h):
    assert h.substantive("attacker-controlled hostname in oneboxed URL") is True


def test_substantive_text_enforces_min_length(h):
    assert h.substantive_text("too short") is False
    assert h.substantive_text("this is a sufficiently long justification") is True


def test_substantive_text_rejects_weak_one_words(h):
    for weak in ("yes", "true", "affected", "works", "passed", "manual"):
        assert h.substantive_text(weak) is False


def test_exact_affected_version_requires_version_or_ref(h):
    assert h.exact_affected_version("affected") is False
    assert h.exact_affected_version("latest") is False
    assert h.exact_affected_version("v3.1.2") is True
    assert h.exact_affected_version("commit a1b2c3d") is True
    assert h.exact_affected_version("3.4") is True


def test_validate_cwe(h):
    assert h.validate_cwe("CWE-918") is True
    assert h.validate_cwe("918") is False
    assert h.validate_cwe("") is False


def test_cvss3_base_score_valid_vector(h):
    score, err = h.cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N")
    assert err == ""
    assert score == 7.5


def test_cvss3_base_score_rejects_bare_number(h):
    score, err = h.cvss3_base_score("5.3")
    assert score is None
    assert "CVSS:3.0 or CVSS:3.1" in err


def test_cvss3_base_score_rejects_empty(h):
    score, _ = h.cvss3_base_score("")
    assert score is None


def test_submission_terminal_and_positive(h):
    assert h.submission_terminal("duplicate") is True
    assert h.submission_terminal("paid") is True
    assert h.submission_terminal("submitted") is False
    assert h.submission_positive("paid") is True
    assert h.submission_positive("duplicate") is False
