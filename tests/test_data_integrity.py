import hashlib
import json
import zipfile
from pathlib import Path

from wappalyzer.analyzers.dom import compile_selector
from wappalyzer.core.analyzer import (
    DETECTION_FIELDS,
    DICT_PATTERN_FIELDS,
    PATTERN_FIELDS,
    build_detector_plan,
)
from wappalyzer.core.matcher import compile_pattern, parse_pattern

DATA = Path(__file__).parent.parent / "wappalyzer" / "data"


def test_fingerprint_lock_matches_bundled_data():
    lock = json.loads((DATA / "fingerprints.lock.json").read_text(encoding="utf-8"))
    technologies = json.loads((DATA / "technologies.json").read_text(encoding="utf-8"))

    assert lock["technology_count"] == len(technologies)
    assert lock["source"].startswith("https://addons.mozilla.org/")
    assert lock["source_identity"] == "wappalyzer@crunchlabz.com"
    assert lock["source_signature"] == "jar-pkcs7-sha256"
    assert len(lock["source_sha256"]) == 64
    assert len(lock["source_signing_ca_sha256"]) == 64
    assert set(lock["files"]) == {
        "categories.json",
        "groups.json",
        "technologies.json",
        "wappalyzer-extension.zip",
    }

    for name, expected_hash in lock["files"].items():
        assert hashlib.sha256((DATA / name).read_bytes()).hexdigest() == expected_hash


def test_extension_and_python_fingerprints_are_identical():
    technologies = json.loads((DATA / "technologies.json").read_text(encoding="utf-8"))
    extension_technologies = {}

    with zipfile.ZipFile(DATA / "wappalyzer-extension.zip") as archive:
        for name in archive.namelist():
            path = Path(name)
            assert not path.is_absolute()
            assert ".." not in path.parts

            if name.startswith("technologies/") and name.endswith(".json"):
                extension_technologies.update(json.loads(archive.read(name)))

    assert extension_technologies == technologies


def test_every_detection_field_is_in_the_compiled_plan():
    technologies = json.loads((DATA / "technologies.json").read_text(encoding="utf-8"))
    plan = build_detector_plan(technologies)

    assert set(plan) == DETECTION_FIELDS

    for field in DETECTION_FIELDS:
        expected = sum(field in technology for technology in technologies.values())
        assert len(plan[field]) == expected


def values(value):
    return value if isinstance(value, list) else [value]


def test_every_official_pattern_and_selector_compiles():
    technologies = json.loads((DATA / "technologies.json").read_text(encoding="utf-8"))
    plan = build_detector_plan(technologies)
    invalid_patterns = []

    for field in PATTERN_FIELDS:
        for name, pattern_group in plan[field]:
            invalid_patterns.extend(
                (field, name, pattern)
                for pattern in values(pattern_group)
                if compile_pattern(pattern)[0] is None
            )

    for field in DICT_PATTERN_FIELDS:
        for name, mapping in plan[field]:
            if not isinstance(mapping, dict):
                continue

            for pattern_group in mapping.values():
                invalid_patterns.extend(
                    (field, name, pattern)
                    for pattern in values(pattern_group)
                    if compile_pattern(pattern)[0] is None
                )

    for name, probes in plan["probe"]:
        invalid_patterns.extend(
            ("probe", name, pattern)
            for pattern in probes.values()
            if compile_pattern(pattern)[0] is None
        )

    invalid_selectors = []

    for name, dom in plan["dom"]:
        selectors = dom.keys() if isinstance(dom, dict) else values(dom)
        invalid_selectors.extend(
            (name, selector)
            for selector in selectors
            if compile_selector(parse_pattern(selector)[0]) is None
        )
        if not isinstance(dom, dict):
            continue
        for rule in dom.values():
            if not isinstance(rule, dict):
                continue
            for field in ("exists", "src", "text"):
                if field in rule and compile_pattern(rule[field])[0] is None:
                    invalid_patterns.append(("dom", name, rule[field]))
            for field in ("attributes", "properties"):
                invalid_patterns.extend(
                    ("dom", name, pattern)
                    for pattern in rule.get(field, {}).values()
                    if compile_pattern(pattern)[0] is None
                )

    assert not invalid_patterns
    assert not invalid_selectors
