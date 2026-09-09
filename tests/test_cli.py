import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from wappalyzer import __main__ as cli
from wappalyzer.__main__ import build_parser
from wappalyzer.models import RunStatus


def test_cli_contract_is_file_only_complete_mode():
    parser = build_parser()
    args = parser.parse_args(["targets.txt"])

    assert args.input_file == "targets.txt"
    assert args.workers is None
    assert args.timeout == 30

    with pytest.raises(SystemExit):
        parser.parse_args(["https://example.test", "--scan-type", "fast"])


def test_cli_accepts_operational_tuning_without_quality_modes():
    parser = build_parser()
    args = parser.parse_args(
        [
            "targets.txt",
            "--workers",
            "32",
            "--timeout",
            "45",
            "--output-dir",
            "artifacts",
        ]
    )

    assert args.workers == 32
    assert args.timeout == 45
    assert args.output_dir == "artifacts"


@pytest.mark.parametrize(("accepted_endpoints", "expected_code"), ((2, 0), (0, 2)))
def test_cli_reports_artifacts_and_rejects_zero_valid_endpoint_runs(
    accepted_endpoints,
    expected_code,
    monkeypatch,
    capsys,
):
    async def run(_args):
        return SimpleNamespace(
            accepted_endpoints=accepted_endpoints,
            canonical_path=Path("generation/canonical.ndjson"),
            generation_path=Path("generation"),
            manifest_path=Path("generation/manifest.json"),
            resumed=False,
            status=RunStatus.COMPLETE,
        )

    monkeypatch.setattr(cli, "_run", run)

    assert cli.main(["targets.txt"]) == expected_code
    captured = capsys.readouterr()
    document = json.loads(captured.out)
    assert document["accepted_endpoints"] == accepted_endpoints
    assert ("no valid endpoints" in captured.err) is (accepted_endpoints == 0)
