import importlib.util
import io
import json
import os
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


def test_index_patch_installs_deterministic_ready_barrier():
    source = """
const Driver = {
  async init() {
    await somethingUnbounded()
  },

  analyzeDom() {
    const result = ({ name, selector, exists, text, property, attribute, value }, index)

    if (typeof property !== 'undefined') {
      return result
    }
  },

  closeCurrentTab(tabId) {
    return tabId
  },
}
"""

    patched = update.patch_index_js(source)

    assert "somethingUnbounded" not in patched
    assert "__WAPPALYZER_SCANNER_READY__" in patched
    assert "initDone()" in patched
    assert "setCachedOption('tracking', false)" in patched
    assert "getSessionOption('tabResults', {})" in patched
    assert "typeof src !== 'undefined'" in patched


def test_upstream_source_hash_is_pinned_to_bundled_generation():
    lock_path = Path(__file__).parent.parent / "wappalyzer" / "data" / "fingerprints.lock.json"
    lock = json.loads(lock_path.read_text(encoding="utf-8"))

    assert lock["source_sha256"] == update.EXPECTED_SOURCE_SHA256


def test_automated_refresh_stages_new_source_hash_for_review(tmp_path):
    source_path = tmp_path / "update.py"
    source_path.write_text(
        f'EXPECTED_SOURCE_SHA256 = "{update.EXPECTED_SOURCE_SHA256}"\n',
        encoding="utf-8",
    )
    new_hash = "a" * 64

    update.write_expected_source_sha256(new_hash, source_path)

    assert source_path.read_text(encoding="utf-8") == (f'EXPECTED_SOURCE_SHA256 = "{new_hash}"\n')


def test_chromium_extension_archive_is_byte_reproducible(tmp_path):
    extension_dir = tmp_path / "extension"
    manifest = {
        "manifest_version": 3,
        "action": {"default_popup": "html/popup.html"},
        "background": {"service_worker": "js/background.js"},
        "permissions": ["cookies", "storage", "tabs", "webRequest"],
        "host_permissions": ["http://*/*", "https://*/*"],
    }
    files = {
        "manifest.json": json.dumps(manifest),
        "html/popup.html": "",
        "js/background.js": "",
        "js/index.js": "",
        "js/content.js": "",
        "technologies/a.json": "{}",
    }

    for relative_path, content in files.items():
        path = extension_dir / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    first_archive = tmp_path / "first.zip"
    second_archive = tmp_path / "second.zip"
    update.write_chromium_extension_archive(extension_dir, first_archive)

    for path in extension_dir.rglob("*"):
        if path.is_file():
            os.utime(path, (2_000_000_000, 2_000_000_000))

    update.write_chromium_extension_archive(extension_dir, second_archive)

    assert first_archive.read_bytes() == second_archive.read_bytes()


def test_generated_bundle_has_complete_scanner_patches():
    archive_path = (
        Path(__file__).parent.parent
        / "wappalyzer"
        / "data"
        / "wappalyzer-extension.zip"
    )

    with zipfile.ZipFile(archive_path) as archive:
        index = archive.read("js/index.js").decode()
        content = archive.read("js/content.js").decode()
        wappalyzer = archive.read("js/wappalyzer.js").decode()

    assert "setCachedOption('tracking', false)" in index
    assert "setCachedOption('showCached', false)" in index
    assert "data-wappalyzer-scanner-state" in content
    assert "function repairSelector(selector)" in content
    assert "src: value" in content
    assert "html: document.documentElement.outerHTML" in content
    assert "html: oo" in wappalyzer
    assert "html: transform(html)" in wappalyzer


def test_generated_publication_rolls_back_on_failure(tmp_path, monkeypatch):
    output_dir = tmp_path / "output"
    data_dir = tmp_path / "data"
    output_dir.mkdir()
    data_dir.mkdir()
    names = ("a.txt", "b.txt", update.FINGERPRINT_LOCK.name)

    for name in names:
        (output_dir / name).write_text(f"new {name}", encoding="utf-8")
        (data_dir / name).write_text(f"old {name}", encoding="utf-8")

    real_replace = update.os.replace
    failed = False

    def fail_mid_publish(source, destination):
        nonlocal failed
        destination = Path(destination)

        if not failed and destination == data_dir / "b.txt":
            failed = True
            raise OSError("injected publication failure")

        return real_replace(source, destination)

    monkeypatch.setattr(update.os, "replace", fail_mid_publish)

    with pytest.raises(OSError, match="injected"):
        update.publish_generated_files(output_dir, data_dir)

    assert {
        name: (data_dir / name).read_text(encoding="utf-8")
        for name in names
    } == {name: f"old {name}" for name in names}
