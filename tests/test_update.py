import importlib.util
import io
import zipfile
from pathlib import Path

import pytest


UPDATE_PATH = Path(__file__).parent.parent / ".github" / "update.py"
SPEC = importlib.util.spec_from_file_location("fingerprint_update", UPDATE_PATH)
update = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(update)


def archive_with(name, content=b"value"):
    buffer = io.BytesIO()

    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr(name, content)

    buffer.seek(0)
    return zipfile.ZipFile(buffer)


def test_safe_extract_rejects_parent_traversal(tmp_path):
    with archive_with("../escape") as archive:
        with pytest.raises(RuntimeError, match="Unsafe archive path"):
            update.safe_extract(archive, tmp_path)


def test_fingerprint_validation_rejects_unknown_relationship():
    technologies = {
        "Example": {
            "cats": [1],
            "implies": "Missing",
        }
    }
    categories = {"1": {"name": "Example", "groups": [1]}}
    groups = {"1": {"name": "Example"}}

    with pytest.raises(RuntimeError, match="unknown technology Missing"):
        update.validate_fingerprints(technologies, categories, groups)
