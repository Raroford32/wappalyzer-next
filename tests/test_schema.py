import copy
import json
import re
from pathlib import Path

import pytest

SCHEMA_PATH = Path(__file__).parent.parent / "wappalyzer" / "schemas" / "scan-run-v1.json"
DIGEST = "a" * 64


def _resolve(root, reference):
    assert reference.startswith("#/")
    value = root
    for part in reference[2:].split("/"):
        value = value[part.replace("~1", "/").replace("~0", "~")]
    return value


def _matches(instance, schema, root):
    try:
        _validate(instance, schema, root)
    except AssertionError:
        return False
    return True


def _validate(instance, schema, root):
    if isinstance(schema, bool):
        assert schema
        return
    if "$ref" in schema:
        _validate(instance, _resolve(root, schema["$ref"]), root)
        return

    for child in schema.get("allOf", ()):
        _validate(instance, child, root)
    if "anyOf" in schema:
        assert any(_matches(instance, child, root) for child in schema["anyOf"])
    if "oneOf" in schema:
        assert sum(_matches(instance, child, root) for child in schema["oneOf"]) == 1
    if "not" in schema:
        assert not _matches(instance, schema["not"], root)
    if "if" in schema:
        branch = "then" if _matches(instance, schema["if"], root) else "else"
        if branch in schema:
            _validate(instance, schema[branch], root)

    if "const" in schema:
        assert instance == schema["const"]
    if "enum" in schema:
        assert instance in schema["enum"]

    expected_type = schema.get("type")
    if expected_type is not None:
        expected_types = expected_type if isinstance(expected_type, list) else [expected_type]
        checks = {
            "array": lambda value: isinstance(value, list),
            "boolean": lambda value: type(value) is bool,
            "integer": lambda value: type(value) is int,
            "null": lambda value: value is None,
            "number": lambda value: type(value) in {int, float},
            "object": lambda value: isinstance(value, dict),
            "string": lambda value: isinstance(value, str),
        }
        assert any(checks[item](instance) for item in expected_types)

    if isinstance(instance, dict):
        properties = schema.get("properties", {})
        assert set(schema.get("required", ())) <= set(instance)
        additional = schema.get("additionalProperties", True)

        for key, value in instance.items():
            if key in properties:
                _validate(value, properties[key], root)
            elif isinstance(additional, dict):
                _validate(value, additional, root)
            else:
                assert additional

    if isinstance(instance, list):
        assert len(instance) >= schema.get("minItems", 0)
        if "maxItems" in schema:
            assert len(instance) <= schema["maxItems"]
        if schema.get("uniqueItems"):
            encoded = [json.dumps(item, sort_keys=True) for item in instance]
            assert len(encoded) == len(set(encoded))
        for index, child in enumerate(schema.get("prefixItems", ())):
            if index < len(instance):
                _validate(instance[index], child, root)
        if isinstance(schema.get("items"), dict):
            for value in instance[len(schema.get("prefixItems", ())) :]:
                _validate(value, schema["items"], root)

    if isinstance(instance, str):
        assert len(instance) >= schema.get("minLength", 0)
        if "maxLength" in schema:
            assert len(instance) <= schema["maxLength"]
        if "pattern" in schema:
            assert re.search(schema["pattern"], instance)

    if type(instance) in {int, float}:
        if "minimum" in schema:
            assert instance >= schema["minimum"]
        if "maximum" in schema:
            assert instance <= schema["maximum"]


def valid_document():
    return {
        "schema_version": "scan-run-v1",
        "run_id": "run-01",
        "occurrence": {
            "sequence": 7,
            "line_number": 9,
            "byte_offset": 42,
            "line_digest": DIGEST,
        },
        "endpoint": {"address": "192.0.2.10", "port": 8443},
        "status": "success",
        "error_codes": [],
        "protocols": [
            {
                "protocol": "http",
                "status": "success",
                "requested_url": "http://192.0.2.10:8443/",
                "effective_url": "http://192.0.2.10:8443/",
                "http_status": 200,
                "tls": {"present": False, "trust": "not_applicable"},
                "stages": [
                    {
                        "name": "static",
                        "status": "success",
                        "error_codes": [],
                    }
                ],
                "technologies": [
                    {
                        "name": "Example",
                        "version": "1",
                        "confidence": 100,
                        "categories": ["Web frameworks"],
                        "groups": ["Core"],
                    }
                ],
                "error_codes": [],
            },
            {
                "protocol": "https",
                "status": "success_empty",
                "requested_url": "https://192.0.2.10:8443/",
                "effective_url": "https://192.0.2.10:8443/",
                "http_status": 204,
                "tls": {
                    "present": True,
                    "trust": "untrusted",
                    "certificate_sha256": "b" * 64,
                },
                "stages": [
                    {
                        "name": "browser",
                        "status": "success_empty",
                        "error_codes": [],
                    }
                ],
                "technologies": [],
                "error_codes": ["tls_untrusted"],
            },
        ],
    }


def test_scan_run_schema_is_versioned_closed_and_accepts_terminal_rows():
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))

    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert schema["$id"].endswith("/scan-run-v1.json")
    assert schema["type"] == "object"
    assert schema["additionalProperties"] is False
    assert schema["properties"]["schema_version"]["const"] == "scan-run-v1"

    _validate(valid_document(), schema, schema)
    invalid_input = valid_document()
    invalid_input.update(
        {
            "endpoint": None,
            "status": "invalid_input",
            "error_codes": ["invalid_input"],
            "protocols": [],
        }
    )
    _validate(invalid_input, schema, schema)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda row: row.update({"schema_version": "scan-run-v2"}),
        lambda row: row.update({"status": "future-status"}),
        lambda row: row.update({"timestamp": "2026-09-09T00:00:00Z"}),
        lambda row: row.update({"raw_error": "Traceback: secret"}),
        lambda row: row.update({"endpoint": None}),
        lambda row: row["occurrence"].pop("line_digest"),
        lambda row: row["protocols"][0].update({"status": "tls_untrusted"}),
    ],
)
def test_scan_run_schema_rejects_unknown_incomplete_or_operational_fields(mutate):
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    document = copy.deepcopy(valid_document())
    mutate(document)

    with pytest.raises(AssertionError):
        _validate(document, schema, schema)
