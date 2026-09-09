import pytest

from wappalyzer.__main__ import build_parser


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
