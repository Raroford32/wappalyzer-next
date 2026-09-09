import json
from pathlib import Path

import pytest
from bs4 import BeautifulSoup

from wappalyzer.browser.analyzer import raw_browser_detections
from wappalyzer.core import analyzer
from wappalyzer.evidence import resolve_raw_detections
from wappalyzer.evidence_limits import EVIDENCE_LIMITS
from wappalyzer.models import CHANNEL_REGISTRY, ChannelOwner

DATA = Path(__file__).parent.parent / "wappalyzer" / "data"

BROWSER_CHANNELS = (
    "cookies",
    "css",
    "dom",
    "headers",
    "html",
    "js",
    "meta",
    "scriptSrc",
    "scripts",
    "text",
    "url",
    "xhr",
)
STATIC_CASES = {
    "certIssuer": (
        "matrix-cert-issuer",
        "Matrix-Cert-Issuer",
        "Other Certificate Authority",
    ),
    "dns": (
        {"TXT": "matrix-dns"},
        {"TXT": ["matrix-dns"]},
        {"TXT": ["other-dns"]},
    ),
    "probe": (
        {"/matrix-probe": "matrix-probe"},
        {"/matrix-probe": (True, "matrix-probe")},
        {"/matrix-probe": (False, "matrix-probe")},
    ),
    "robots": (
        "matrix-robots",
        "Disallow: /matrix-robots",
        "Disallow: /other",
    ),
}
FINGERPRINT_METADATA_FIELDS = {
    "cats",
    "cpe",
    "description",
    "excludes",
    "icon",
    "implies",
    "oss",
    "pricing",
    "requires",
    "requiresCategory",
    "saas",
    "website",
}


def static_evidence(channel, value):
    evidence = {
        name: {} if name in analyzer.DICT_PATTERN_FIELDS else ""
        for name in analyzer.DETECTION_FIELDS
    }
    evidence["dom"] = BeautifulSoup("<main></main>", "html.parser")
    evidence["probes"] = {}
    evidence["_truncations"] = {}
    evidence["probes" if channel == "probe" else channel] = value
    return evidence


@pytest.mark.parametrize("channel", tuple(STATIC_CASES))
def test_static_channel_positive_and_negative_fixtures_are_operational(channel, monkeypatch):
    pattern, positive, negative = STATIC_CASES[channel]
    technology = f"Matrix {channel}"
    detector_plan = {
        name: ((technology, pattern),) if name == channel else ()
        for name in analyzer.DETECTION_FIELDS
    }
    monkeypatch.setattr(analyzer, "DETECTOR_PLAN", detector_plan)

    positive_detections = analyzer.collect_raw_detections(
        static_evidence(channel, positive),
        owner=ChannelOwner.STATIC,
    )
    negative_detections = analyzer.collect_raw_detections(
        static_evidence(channel, negative),
        owner=ChannelOwner.STATIC,
    )

    assert [(item.technology, item.channel) for item in positive_detections] == [
        (technology, channel)
    ]
    assert resolve_raw_detections(positive_detections)[0].name == technology
    assert negative_detections == ()


@pytest.mark.parametrize("channel", BROWSER_CHANNELS)
def test_browser_channel_positive_and_wrong_owner_fixtures_preserve_provenance(channel):
    technology = f"Matrix {channel}"
    positive = {
        "technology": technology,
        "version": "1.2.3",
        "pattern": {
            "type": f"{channel}.matrix",
            "regex": "matrix-positive",
            "confidence": 100,
            "match": "matrix-positive",
        },
        "lastUrl": "http://192.0.2.1:8080/positive",
    }
    wrong_owner = {
        **positive,
        "pattern": {**positive["pattern"], "type": "certIssuer.matrix"},
    }

    detections = raw_browser_detections((positive, wrong_owner))

    assert [(item.technology, item.channel, item.version) for item in detections] == [
        (technology, channel, "1.2.3")
    ]
    assert resolve_raw_detections(detections)[0].name == technology


def test_channel_registry_fixture_ids_resolve_to_executable_matrix_cases():
    executable_cases = {
        f"channels/{channel}/{polarity}"
        for channel in CHANNEL_REGISTRY
        for polarity in ("positive", "negative")
    }

    assert set(EVIDENCE_LIMITS) == set(CHANNEL_REGISTRY)
    for channel, registration in CHANNEL_REGISTRY.items():
        assert registration.positive_fixture in executable_cases, channel
        assert registration.negative_fixture in executable_cases, channel
        expected_owner = ChannelOwner.STATIC if channel in STATIC_CASES else ChannelOwner.BROWSER
        assert registration.owner is expected_owner


def test_upstream_fingerprint_schema_cannot_add_or_remove_a_channel_silently():
    technologies = json.loads((DATA / "technologies.json").read_text(encoding="utf-8"))
    observed_fields = {field for technology in technologies.values() for field in technology}
    observed_channels = observed_fields - FINGERPRINT_METADATA_FIELDS

    assert observed_channels == set(CHANNEL_REGISTRY) == analyzer.DETECTION_FIELDS
