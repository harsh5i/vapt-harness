"""Field validators the promotion/report gates depend on.

Pure leaf layer: only the stdlib `re`. No dependency on harness globals or run
state. Covers CWE/CVSS vector validation, the substantive/placeholder checks,
exact affected-version detection, and submission-status predicates.
"""
from __future__ import annotations

import re
from typing import Any


CVSS3_METRICS = {
    "AV": {"N", "A", "L", "P"},
    "AC": {"L", "H"},
    "PR": {"N", "L", "H"},
    "UI": {"N", "R"},
    "S": {"U", "C"},
    "C": {"N", "L", "H"},
    "I": {"N", "L", "H"},
    "A": {"N", "L", "H"},
}


def validate_cwe(value: str) -> bool:
    return bool(re.fullmatch(r"CWE-\d{1,5}", str(value or "").strip(), flags=re.IGNORECASE))


def parse_cvss3(vector: str) -> tuple[dict[str, str] | None, str]:
    raw = str(vector or "").strip()
    if not raw:
        return None, "empty"
    parts = raw.split("/")
    if parts[0] not in {"CVSS:3.0", "CVSS:3.1"}:
        return None, "must start with CVSS:3.0 or CVSS:3.1"
    metrics: dict[str, str] = {}
    for part in parts[1:]:
        if ":" not in part:
            return None, f"invalid metric: {part}"
        key, value = part.split(":", 1)
        if key not in CVSS3_METRICS or value not in CVSS3_METRICS[key]:
            return None, f"invalid metric: {part}"
        metrics[key] = value
    missing = [key for key in CVSS3_METRICS if key not in metrics]
    if missing:
        return None, "missing metrics: " + ",".join(missing)
    return metrics, ""


def _cvss_round_up(value: float) -> float:
    return int(value * 10 + 0.999999) / 10.0


def cvss3_base_score(vector: str) -> tuple[float | None, str]:
    metrics, err = parse_cvss3(vector)
    if not metrics:
        return None, err
    av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}[metrics["AV"]]
    ac = {"L": 0.77, "H": 0.44}[metrics["AC"]]
    ui = {"N": 0.85, "R": 0.62}[metrics["UI"]]
    pr_values = {
        "U": {"N": 0.85, "L": 0.62, "H": 0.27},
        "C": {"N": 0.85, "L": 0.68, "H": 0.50},
    }
    pr = pr_values[metrics["S"]][metrics["PR"]]
    cia = {"N": 0.0, "L": 0.22, "H": 0.56}
    iss = 1 - ((1 - cia[metrics["C"]]) * (1 - cia[metrics["I"]]) * (1 - cia[metrics["A"]]))
    if metrics["S"] == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
    exploitability = 8.22 * av * ac * pr * ui
    if impact <= 0:
        return 0.0, ""
    if metrics["S"] == "U":
        return _cvss_round_up(min(impact + exploitability, 10)), ""
    return _cvss_round_up(min(1.08 * (impact + exploitability), 10)), ""


def substantive(value: Any) -> bool:
    return value not in (None, "", "unchecked", []) and str(value).strip().lower() not in {
        "x",
        "todo",
        "tbd",
        "n/a",
    }


def substantive_text(value: Any, min_chars: int = 18) -> bool:
    if not substantive(value):
        return False
    text = re.sub(r"\s+", " ", str(value)).strip()
    if len(text) < min_chars:
        return False
    weak_values = {
        "yes",
        "true",
        "affected",
        "works",
        "passed",
        "unknown",
        "not checked",
        "manual",
    }
    return text.lower() not in weak_values


def exact_affected_version(value: Any) -> bool:
    if not substantive(value):
        return False
    text = str(value).strip()
    if text.lower() in {"yes", "true", "affected", "latest"}:
        return False
    return bool(re.search(r"(v?\d+\.\d+|commit|sha|tag|release|main@|[a-f0-9]{7,40})", text, flags=re.IGNORECASE))


def submission_positive(status: str) -> bool:
    return str(status or "").lower() in {"triaged", "resolved", "paid", "accepted", "valid", "informative"}


def submission_terminal(status: str) -> bool:
    return str(status or "").lower() in {
        "triaged",
        "duplicate",
        "n_a",
        "resolved",
        "paid",
        "accepted",
        "valid",
        "informative",
        "rejected",
        "not_applicable",
        "out_of_scope",
    }
