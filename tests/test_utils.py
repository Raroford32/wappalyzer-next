import pytest

from wappalyzer.core import utils


@pytest.fixture
def graph(monkeypatch):
    database = {
        "A": {"cats": [], "implies": r"B\;confidence:80", "excludes": "D"},
        "B": {"cats": [], "implies": r"C\;version:2"},
        "C": {"cats": []},
        "D": {"cats": [], "excludes": "A"},
        "Parent": {"cats": [7]},
        "Plugin": {"cats": [], "requires": "Parent"},
        "CategoryPlugin": {"cats": [], "requiresCategory": 7},
        "SelfSatisfying": {
            "cats": [],
            "implies": "Parent",
            "requires": "Parent",
        },
        "Implying": {"cats": [], "implies": "Restricted"},
        "Restricted": {"cats": [], "requires": "Parent"},
        "OtherCategory": {"cats": [8]},
        "EitherGate": {
            "cats": [],
            "requires": "Parent",
            "requiresCategory": 8,
        },
    }
    monkeypatch.setattr(utils, "tech_db", database)
    return database


def test_implies_are_recursive_and_preserve_metadata(graph):
    result = utils.create_result({"A": {"version": "1", "confidence": 90}})

    assert list(result) == ["A", "B", "C"]
    assert result["B"]["confidence"] == 80
    assert result["C"]["confidence"] == 80
    assert result["C"]["version"] == "2"


def test_requires_gate_instead_of_inventing_parent(graph):
    assert utils.create_result({"Plugin": {"version": "", "confidence": 100}}) == {}

    result = utils.create_result(
        {
            "Parent": {"version": "", "confidence": 100},
            "Plugin": {"version": "", "confidence": 100},
        }
    )
    assert list(result) == ["Parent", "Plugin"]


def test_requires_category_is_enforced(graph):
    assert utils.create_result({"CategoryPlugin": {"version": "", "confidence": 100}}) == {}

    result = utils.create_result(
        {
            "CategoryPlugin": {"version": "", "confidence": 100},
            "Parent": {"version": "", "confidence": 100},
        }
    )
    assert list(result) == ["CategoryPlugin", "Parent"]


def test_mutual_exclusion_is_deterministic(graph):
    result = utils.create_result(
        {
            "D": {"version": "", "confidence": 100},
            "A": {"version": "", "confidence": 100},
        }
    )

    assert "A" in result
    assert "D" not in result


def test_direct_detection_beats_implied_detection(graph):
    result = utils.create_result(
        {
            "A": {"version": "", "confidence": 100},
            "B": {"version": "3", "confidence": 95},
        }
    )

    assert result["B"]["version"] == "3"
    assert result["B"]["confidence"] == 95


def test_implication_never_changes_existing_direct_evidence(graph):
    result = utils.create_result(
        {
            "A": {"version": "", "confidence": 100},
            "B": {"version": "", "confidence": 25},
        }
    )

    assert result["B"]["version"] == ""
    assert result["B"]["confidence"] == 25


def test_zero_confidence_signal_does_not_detect_technology(graph):
    assert utils.create_result({"A": {"version": "1", "confidence": 0}}) == {}


def test_technology_cannot_satisfy_its_own_requirement(graph):
    result = utils.create_result({"SelfSatisfying": {"version": "", "confidence": 100}})

    assert result == {}


def test_implied_technology_is_not_rejected_by_direct_detection_gates(graph):
    result = utils.create_result({"Implying": {"version": "", "confidence": 100}})

    assert list(result) == ["Implying", "Restricted"]


def test_requirement_name_and_category_are_alternative_triggers(graph):
    result = utils.create_result(
        {
            "EitherGate": {"version": "", "confidence": 100},
            "OtherCategory": {"version": "", "confidence": 100},
        }
    )

    assert list(result) == ["EitherGate", "OtherCategory"]
