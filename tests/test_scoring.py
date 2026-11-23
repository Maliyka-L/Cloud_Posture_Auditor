from scoring import calculate_risk
from analytics import calculate_severity_counts


def make(*severities):
    return [{"severity": severity} for severity in severities]


def test_no_findings_is_grade_a():
    assert calculate_risk([]) == (0, "A")


def test_weights():
    score, _ = calculate_risk(make("HIGH", "MEDIUM", "LOW"))
    assert score == 9


def test_grades():
    assert calculate_risk(make("HIGH"))[1] == "B"
    assert calculate_risk(make("HIGH", "HIGH"))[1] == "C"
    assert calculate_risk(make(*["HIGH"] * 4))[1] == "D"
    assert calculate_risk(make(*["HIGH"] * 5))[1] == "F"


def test_severity_counts():
    counts = calculate_severity_counts(make("HIGH", "HIGH", "MEDIUM", "LOW"))
    assert counts == {"high": 2, "medium": 1, "low": 1}
