import hashlib
import json
import os
import re
import shutil
import tempfile
import urllib.request
import zipfile
from pathlib import Path


DEFAULT_URL = (
    "https://addons.mozilla.org/firefox/downloads/latest/wappalyzer/platform:2/wappalyzer.xpi"
)
URL = os.getenv("WAPPALYZER_EXTENSION_URL", DEFAULT_URL)
REPO_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = REPO_ROOT / "wappalyzer" / "data"
EXTENSION_ARCHIVE = DATA_DIR / "wappalyzer-extension.zip"
FINGERPRINT_LOCK = DATA_DIR / "fingerprints.lock.json"

PROMPT_BLOCK = re.compile(
    r"^[ \t]*const current = await get(?:Cached)?Option\('version'\)\n"
    r".*?"
    r"(?=^[ \t]*initDone\(\))",
    re.MULTILINE | re.DOTALL,
)


def patch_index_js(content):
    content = PROMPT_BLOCK.sub("", content, count=1)

    if "https://www.wappalyzer.com/installed/" in content:
        raise RuntimeError("Failed to remove install prompt from js/index.js")

    if "https://www.wappalyzer.com/upgraded/" in content:
        raise RuntimeError("Failed to remove upgrade prompt from js/index.js")

    return content


def patch_manifest_for_chromium(manifest):
    manifest = json.loads(json.dumps(manifest))
    manifest.pop("browser_specific_settings", None)
    manifest.pop("applications", None)

    background = manifest.get("background")

    if isinstance(background, dict) and background.get("service_worker"):
        background.pop("scripts", None)

    return manifest


def validate_manifest(manifest):
    errors = []

    if manifest.get("manifest_version") != 3:
        errors.append("manifest_version must be 3")

    if manifest.get("action", {}).get("default_popup") != "html/popup.html":
        errors.append("action.default_popup must be html/popup.html")

    if not manifest.get("background", {}).get("service_worker"):
        errors.append("background.service_worker is required")

    if "scripts" in manifest.get("background", {}):
        errors.append("background.scripts must be removed for Chromium MV3")

    permissions = set(manifest.get("permissions", []))
    host_permissions = set(manifest.get("host_permissions", []))

    for permission in ("cookies", "storage", "tabs", "webRequest"):
        if permission not in permissions:
            errors.append(f"missing permission: {permission}")

    for host_permission in ("http://*/*", "https://*/*"):
        if host_permission not in host_permissions:
            errors.append(f"missing host permission: {host_permission}")

    if "browser_specific_settings" in manifest:
        errors.append("browser_specific_settings must be removed")

    if "applications" in manifest:
        errors.append("applications must be removed")

    if errors:
        raise RuntimeError("Invalid Chromium extension manifest: " + "; ".join(errors))


def validate_extension_tree(extension_dir, require_technologies=False):
    required_files = (
        "manifest.json",
        "html/popup.html",
        "js/background.js",
        "js/index.js",
        "js/content.js",
    )

    for relative_path in required_files:
        if not (extension_dir / relative_path).is_file():
            raise RuntimeError(f"Missing extension file: {relative_path}")

    if require_technologies and not any((extension_dir / "technologies").glob("*.json")):
        raise RuntimeError("Missing extension technology fingerprint files")

    validate_manifest(json.loads((extension_dir / "manifest.json").read_text(encoding="utf-8")))


def safe_extract(archive, destination):
    destination = destination.resolve()

    for member in archive.infolist():
        target = (destination / member.filename).resolve()

        if destination not in target.parents and target != destination:
            raise RuntimeError(f"Unsafe archive path: {member.filename}")

    archive.extractall(destination)


def relationship_names(value):
    values = value if isinstance(value, list) else [value]
    return [item.split(r"\;", 1)[0] for item in values]


def validate_fingerprints(technologies, categories, groups):
    errors = []

    for name, technology in technologies.items():
        for category in technology.get("cats", []):
            if str(category) not in categories:
                errors.append(f"{name}: unknown category {category}")

        for field in ("implies", "requires", "excludes"):
            for related_name in relationship_names(technology.get(field, [])):
                if related_name and related_name not in technologies:
                    errors.append(f"{name}: {field} references unknown technology {related_name}")

        required_categories = technology.get("requiresCategory", [])
        required_categories = (
            required_categories if isinstance(required_categories, list) else [required_categories]
        )

        for category in required_categories:
            if str(category) not in categories:
                errors.append(f"{name}: requires unknown category {category}")

    for category_id, category in categories.items():
        for group in category.get("groups", []):
            if str(group) not in groups:
                errors.append(f"category {category_id}: unknown group {group}")

    if errors:
        preview = "; ".join(errors[:20])
        raise RuntimeError(f"Invalid fingerprint graph ({len(errors)} errors): {preview}")


def write_chromium_extension_archive(extension_dir, archive_path):
    manifest_path = extension_dir / "manifest.json"
    manifest_path.write_text(
        json.dumps(
            patch_manifest_for_chromium(json.loads(manifest_path.read_text(encoding="utf-8"))),
            separators=(",", ":"),
        ),
        encoding="utf-8",
    )
    validate_extension_tree(extension_dir, require_technologies=True)

    with zipfile.ZipFile(archive_path, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(extension_dir.rglob("*")):
            if path.is_file():
                archive.write(path, path.relative_to(extension_dir))


def main():
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="wappalyzer-update-") as tempdir:
        tempdir = Path(tempdir)
        archive_path = tempdir / "wappalyzer.xpi"
        extract_dir = tempdir / "wappalyzer"

        request = urllib.request.Request(
            URL,
            headers={"User-Agent": "wappalyzer-next fingerprint updater"},
        )

        with urllib.request.urlopen(request, timeout=60) as response:
            archive_bytes = response.read()

        archive_path.write_bytes(archive_bytes)

        with zipfile.ZipFile(archive_path) as archive:
            safe_extract(archive, extract_dir)

        index_path = extract_dir / "js" / "index.js"
        index_path.write_text(
            patch_index_js(index_path.read_text(encoding="utf-8")),
            encoding="utf-8",
        )

        technologies = {}
        for path in sorted((extract_dir / "technologies").glob("*.json")):
            technologies.update(json.loads(path.read_text(encoding="utf-8")))

        categories = json.loads(
            (extract_dir / "categories.json").read_text(encoding="utf-8")
        )
        groups = json.loads(
            (extract_dir / "groups.json").read_text(encoding="utf-8")
        )
        validate_fingerprints(technologies, categories, groups)

        (DATA_DIR / "technologies.json").write_text(
            json.dumps(technologies, indent=4) + "\n",
            encoding="utf-8",
        )
        shutil.copy2(extract_dir / "groups.json", DATA_DIR / "groups.json")
        shutil.copy2(extract_dir / "categories.json", DATA_DIR / "categories.json")

        write_chromium_extension_archive(extract_dir, EXTENSION_ARCHIVE)
        manifest = json.loads(
            (extract_dir / "manifest.json").read_text(encoding="utf-8")
        )
        FINGERPRINT_LOCK.write_text(
            json.dumps(
                {
                    "source": URL,
                    "source_sha256": hashlib.sha256(archive_bytes).hexdigest(),
                    "extension_version": manifest.get("version"),
                    "technology_count": len(technologies),
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )


if __name__ == "__main__":
    main()
