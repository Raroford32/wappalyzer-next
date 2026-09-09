import hashlib
import json
from types import MappingProxyType

from wappalyzer.models import CHANNEL_REGISTRY

BROWSER_TEXT_CHARACTER_LIMIT = 25_000
BROWSER_INLINE_SCRIPT_COUNT_LIMIT = 50
BROWSER_INLINE_SCRIPT_CHARACTER_LIMIT = 200_000
BROWSER_DOM_TEXT_CHARACTER_LIMIT = 1_000_000
BROWSER_HTML_CHARACTER_LIMIT = 2_000_000
BROWSER_DOM_DETECTIONS_PER_TECH_LIMIT = 50
COMPLETE_PROBE_COUNT_LIMIT = 64
COMPLETE_PROBE_ITEM_BYTES_LIMIT = 2 * 1024 * 1024

_LIMITS = {
    channel: {
        "max_count": None,
        "max_characters": None,
        "max_item_bytes": None,
    }
    for channel in CHANNEL_REGISTRY
}
_LIMITS["dom"].update(
    max_count=BROWSER_DOM_DETECTIONS_PER_TECH_LIMIT,
    max_characters=BROWSER_DOM_TEXT_CHARACTER_LIMIT,
)
_LIMITS["html"]["max_characters"] = BROWSER_HTML_CHARACTER_LIMIT
_LIMITS["probe"].update(
    max_count=COMPLETE_PROBE_COUNT_LIMIT,
    max_item_bytes=COMPLETE_PROBE_ITEM_BYTES_LIMIT,
)
_LIMITS["scripts"].update(
    max_count=BROWSER_INLINE_SCRIPT_COUNT_LIMIT,
    max_characters=BROWSER_INLINE_SCRIPT_CHARACTER_LIMIT,
)
_LIMITS["text"]["max_characters"] = BROWSER_TEXT_CHARACTER_LIMIT

EVIDENCE_LIMITS = MappingProxyType(
    {channel: MappingProxyType(dict(policy)) for channel, policy in sorted(_LIMITS.items())}
)


def evidence_limits_bytes():
    return json.dumps(
        {channel: dict(policy) for channel, policy in EVIDENCE_LIMITS.items()},
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


EVIDENCE_LIMITS_SHA256 = hashlib.sha256(evidence_limits_bytes()).hexdigest()


__all__ = [
    "BROWSER_DOM_DETECTIONS_PER_TECH_LIMIT",
    "BROWSER_DOM_TEXT_CHARACTER_LIMIT",
    "BROWSER_HTML_CHARACTER_LIMIT",
    "BROWSER_INLINE_SCRIPT_CHARACTER_LIMIT",
    "BROWSER_INLINE_SCRIPT_COUNT_LIMIT",
    "BROWSER_TEXT_CHARACTER_LIMIT",
    "COMPLETE_PROBE_COUNT_LIMIT",
    "COMPLETE_PROBE_ITEM_BYTES_LIMIT",
    "EVIDENCE_LIMITS",
    "EVIDENCE_LIMITS_SHA256",
    "evidence_limits_bytes",
]
