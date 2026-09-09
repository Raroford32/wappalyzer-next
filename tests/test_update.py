import base64
import hashlib
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


def signed_source_archive(
    *,
    extension_id=update.EXPECTED_EXTENSION_ID,
    extension_name=update.EXPECTED_EXTENSION_NAME,
    version="6.12.6",
    extra_files=None,
):
    members = {
        "manifest.json": json.dumps(
            {
                "name": extension_name,
                "version": version,
                "manifest_version": 3,
                "browser_specific_settings": {"gecko": {"id": extension_id}},
            },
            separators=(",", ":"),
        ).encode(),
        "payload.txt": b"authenticated payload",
    }
    members.update(extra_files or {})
    sections = ["Manifest-Version: 1.0", ""]
    for name, content in sorted(members.items()):
        digest = base64.b64encode(hashlib.sha256(content).digest()).decode()
        sections.extend(
            (
                f"Name: {name}",
                "Digest-Algorithms: SHA256",
                f"SHA256-Digest: {digest}",
                "",
            )
        )
    content_manifest = "\n".join(sections).encode()
    manifest_digest = base64.b64encode(hashlib.sha256(content_manifest).digest()).decode()
    signature_manifest = (
        f"Signature-Version: 1.0\nSHA256-Digest-Manifest: {manifest_digest}\n"
    ).encode()
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, content in members.items():
            archive.writestr(name, content)
        archive.writestr("META-INF/manifest.mf", content_manifest)
        archive.writestr("META-INF/mozilla.sf", signature_manifest)
        archive.writestr("META-INF/mozilla.rsa", b"publisher signature")
    return buffer.getvalue()


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


def test_fingerprint_validation_fails_closed_on_schema_drift():
    technology = {
        "cats": [1],
        **{field: {} for field in update.SUPPORTED_DETECTION_FIELDS},
        "newUpstreamChannel": "marker",
    }
    categories = {"1": {"name": "Example", "groups": [1]}}
    groups = {"1": {"name": "Example"}}

    with pytest.raises(RuntimeError, match="unsupported fingerprint fields"):
        update.validate_fingerprints({"Example": technology}, categories, groups)

    technology.pop("newUpstreamChannel")
    technology.pop("xhr")

    with pytest.raises(RuntimeError, match="missing detection fields"):
        update.validate_fingerprints({"Example": technology}, categories, groups)


def test_source_archive_requires_official_identity_digest_and_signed_members(monkeypatch):
    archive_bytes = signed_source_archive()
    source_digest = hashlib.sha256(archive_bytes).hexdigest()
    verified = []

    monkeypatch.setattr(
        update,
        "verify_publisher_signature",
        lambda signature, signed_content, **kwargs: verified.append(
            (signature, signed_content, kwargs)
        ),
    )
    provenance = update.validate_source_archive(
        archive_bytes,
        expected_source_sha256=source_digest,
    )

    assert provenance == {
        "extension_id": update.EXPECTED_EXTENSION_ID,
        "extension_version": "6.12.6",
        "signature_format": update.SOURCE_SIGNATURE_FORMAT,
        "signing_ca_sha256": update.EXPECTED_SIGNING_CA_SHA256,
        "source_sha256": source_digest,
    }
    assert verified and verified[0][0] == b"publisher signature"

    with pytest.raises(RuntimeError, match="official endpoint"):
        update.validate_source_archive(
            archive_bytes,
            source_url="https://attacker.invalid/wappalyzer.xpi",
            expected_source_sha256=source_digest,
        )
    with pytest.raises(RuntimeError, match="Upstream extension changed"):
        update.validate_source_archive(
            archive_bytes,
            expected_source_sha256="0" * 64,
        )


def test_source_update_override_never_bypasses_identity_or_content_authentication(monkeypatch):
    monkeypatch.setattr(update, "verify_publisher_signature", lambda *_args, **_kwargs: None)
    wrong_identity = signed_source_archive(extension_id="attacker@example.invalid")

    with pytest.raises(RuntimeError, match="identity"):
        update.validate_source_archive(
            wrong_identity,
            expected_source_sha256="0" * 64,
            accept_source_update=True,
        )

    source = io.BytesIO(signed_source_archive())
    modified = io.BytesIO()
    with zipfile.ZipFile(source) as original, zipfile.ZipFile(modified, "w") as output:
        for item in original.infolist():
            output.writestr(item, original.read(item))
        output.writestr("unsigned.txt", b"unsigned")
    archive_bytes = modified.getvalue()
    with pytest.raises(RuntimeError, match="signed-member set mismatch"):
        update.validate_source_archive(
            archive_bytes,
            expected_source_sha256="0" * 64,
            accept_source_update=True,
        )


def test_source_archive_detects_tampering_after_signature(monkeypatch):
    archive_bytes = signed_source_archive()
    source = io.BytesIO(archive_bytes)
    tampered = io.BytesIO()
    with zipfile.ZipFile(source) as original, zipfile.ZipFile(tampered, "w") as modified:
        for item in original.infolist():
            content = original.read(item)
            if item.filename == "payload.txt":
                content = b"tampered payload"
            modified.writestr(item, content)

    monkeypatch.setattr(update, "verify_publisher_signature", lambda *_args, **_kwargs: None)
    tampered_bytes = tampered.getvalue()
    with pytest.raises(RuntimeError, match="digest mismatch"):
        update.validate_source_archive(
            tampered_bytes,
            expected_source_sha256=hashlib.sha256(tampered_bytes).hexdigest(),
        )


def test_bundled_publisher_signature_chains_to_pinned_mozilla_ca():
    archive_path = Path(__file__).parent.parent / "wappalyzer" / "data" / "wappalyzer-extension.zip"
    with zipfile.ZipFile(archive_path) as archive:
        signature = archive.read("META-INF/mozilla.rsa")
        signature_manifest = archive.read("META-INF/mozilla.sf")

    update.verify_publisher_signature(signature, signature_manifest)

    with pytest.raises(RuntimeError, match="signature verification failed"):
        update.verify_publisher_signature(signature, signature_manifest + b"tampered")


def test_index_patch_installs_deterministic_ready_barrier():
    source = """
const Driver = {
  async init() {
    await somethingUnbounded()
  },

  closeCurrentTab(tabId) {
    return tabId
  },

  async onXhrRequestComplete(request) {
    setTimeout(() => {
      return request
      }, 1000)
  },

  /**
   * Get detections
   */
  async getDetectionsForTab(tab) {
    return tab
  },

  analyzeDom() {
    const result = ({ name, selector, exists, text, property, attribute, value }, index)

            if (typeof property !== 'undefined') {
      return result
    }
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
    assert "getRawDetectionsForTab(tab)" in patched
    assert "isSameOriginUrl(url, lastUrl)" in patched
    assert "}, 0)" in patched


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
    archive_path = Path(__file__).parent.parent / "wappalyzer" / "data" / "wappalyzer-extension.zip"

    with zipfile.ZipFile(archive_path) as archive:
        index = archive.read("js/index.js").decode()
        content = archive.read("js/content.js").decode()
        wappalyzer = archive.read("js/wappalyzer.js").decode()

    assert "setCachedOption('tracking', false)" in index
    assert "setCachedOption('showCached', false)" in index
    assert "getRawDetectionsForTab(tab)" in index
    assert "isSameOriginUrl(url, lastUrl)" in index
    assert "async onXhrRequestComplete(request)" in index
    xhr_handler = index.split("async onXhrRequestComplete(request)", 1)[1].split(
        "\n  },\n\n  /**",
        1,
    )[0]
    assert "}, 0)" in xhr_handler
    assert "data-wappalyzer-scanner-state" in content
    assert "data-wappalyzer-dom-truncated" in content
    assert "return !!(html || text || css || scripts.length)" in content
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

    assert {name: (data_dir / name).read_text(encoding="utf-8") for name in names} == {
        name: f"old {name}" for name in names
    }
