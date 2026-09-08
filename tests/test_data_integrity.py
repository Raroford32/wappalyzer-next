import json
import zipfile
from pathlib import Path

from wappalyzer.core.analyzer import DETECTION_FIELDS, build_detector_plan


DATA = Path(__file__).parent.parent / "wappalyzer" / "data"


def test_fingerprint_lock_matches_bundled_data():
    lock = json.loads((DATA / "fingerprints.lock.json").read_text(encoding="utf-8"))
    technologies = json.loads((DATA / "technologies.json").read_text(encoding="utf-8"))

    assert lock["technology_count"] == len(technologies)
    assert lock["source"].startswith("https://addons.mozilla.org/")
    assert len(lock["source_sha256"]) == 64


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
