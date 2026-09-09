import hashlib
import json

from wappalyzer.evidence_limits import (
    BROWSER_DOM_DETECTIONS_PER_TECH_LIMIT,
    BROWSER_DOM_TEXT_CHARACTER_LIMIT,
    BROWSER_HTML_CHARACTER_LIMIT,
    BROWSER_INLINE_SCRIPT_CHARACTER_LIMIT,
    BROWSER_INLINE_SCRIPT_COUNT_LIMIT,
    BROWSER_TEXT_CHARACTER_LIMIT,
    EVIDENCE_LIMITS,
    EVIDENCE_LIMITS_SHA256,
    evidence_limits_bytes,
)
from wappalyzer.models import CHANNEL_REGISTRY


def test_evidence_limit_policy_is_complete_canonical_and_manifest_hashable():
    assert set(EVIDENCE_LIMITS) == set(CHANNEL_REGISTRY)
    assert all(
        set(policy)
        == {
            "max_count",
            "max_characters",
            "max_item_bytes",
        }
        for policy in EVIDENCE_LIMITS.values()
    )
    assert (
        evidence_limits_bytes()
        == json.dumps(
            {channel: dict(policy) for channel, policy in EVIDENCE_LIMITS.items()},
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    )
    assert EVIDENCE_LIMITS_SHA256 == hashlib.sha256(evidence_limits_bytes()).hexdigest()


def test_browser_limit_constants_match_generated_extension_contract():
    assert BROWSER_TEXT_CHARACTER_LIMIT == 25_000
    assert BROWSER_INLINE_SCRIPT_COUNT_LIMIT == 50
    assert BROWSER_INLINE_SCRIPT_CHARACTER_LIMIT == 200_000
    assert BROWSER_DOM_TEXT_CHARACTER_LIMIT == 1_000_000
    assert BROWSER_HTML_CHARACTER_LIMIT == 2_000_000
    assert BROWSER_DOM_DETECTIONS_PER_TECH_LIMIT == 50
    assert EVIDENCE_LIMITS["dom"]["max_count"] == 50
    assert EVIDENCE_LIMITS["html"]["max_characters"] == 2_000_000
    assert EVIDENCE_LIMITS["scripts"]["max_count"] == 50
    assert EVIDENCE_LIMITS["scripts"]["max_characters"] == 200_000
    assert EVIDENCE_LIMITS["text"]["max_characters"] == 25_000
