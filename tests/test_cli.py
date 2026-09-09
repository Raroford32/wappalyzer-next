import asyncio
import json
import runpy
import signal
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

import wappalyzer.__main__ as cli
import wappalyzer.direct as direct_module
from wappalyzer.__main__ import build_parser, positive_int
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


@pytest.mark.parametrize(
    ("value", "message"),
    [
        ("many", "'many' is not an integer"),
        ("0", "value must be at least 1"),
    ],
)
def test_positive_int_rejects_nonnumeric_and_nonpositive_values(value, message):
    with pytest.raises(Exception, match=message):
        positive_int(value)


def test_run_forwards_configuration_and_removes_installed_signal_handlers(monkeypatch):
    calls = []
    expected = object()

    class SignalLoop:
        def add_signal_handler(self, signum, callback):
            calls.append(("add", signum, callback))

        def remove_signal_handler(self, signum):
            calls.append(("remove", signum))
            return True

    async def fake_direct_scan(input_file, **kwargs):
        calls.append(("scan", input_file, kwargs))
        return expected

    args = SimpleNamespace(
        input_file="targets.txt",
        output_dir="artifacts",
        workers=3,
        timeout=9,
    )

    async def exercise():
        with monkeypatch.context() as patch:
            patch.setattr(cli.asyncio, "get_running_loop", lambda: SignalLoop())
            patch.setattr(cli, "run_direct_scan", fake_direct_scan)
            return await cli._run(args)

    assert asyncio.run(exercise()) is expected
    assert [(call[0], call[1]) for call in calls if call[0] == "add"] == [
        ("add", signal.SIGINT),
        ("add", signal.SIGTERM),
    ]
    assert calls[-3:] == [
        (
            "scan",
            "targets.txt",
            {"output_root": "artifacts", "workers": 3, "timeout": 9},
        ),
        ("remove", signal.SIGINT),
        ("remove", signal.SIGTERM),
    ]


def test_run_continues_when_platform_signal_handlers_are_unavailable(monkeypatch):
    calls = []

    class UnsupportedSignalLoop:
        def add_signal_handler(self, signum, _callback):
            calls.append(("add", signum))
            if signum == signal.SIGINT:
                raise NotImplementedError
            raise RuntimeError("not in main thread")

        def remove_signal_handler(self, signum):
            calls.append(("unexpected remove", signum))

    async def fake_direct_scan(*_args, **_kwargs):
        return "completed"

    args = SimpleNamespace(input_file="targets.txt", output_dir=None, workers=None, timeout=30)

    async def exercise():
        with monkeypatch.context() as patch:
            patch.setattr(cli.asyncio, "get_running_loop", lambda: UnsupportedSignalLoop())
            patch.setattr(cli, "run_direct_scan", fake_direct_scan)
            return await cli._run(args)

    assert asyncio.run(exercise()) == "completed"
    assert calls == [("add", signal.SIGINT), ("add", signal.SIGTERM)]


def test_installed_signal_handler_cancels_scan_and_is_removed(monkeypatch):
    callbacks = {}
    removed = []

    class SignalLoop:
        def add_signal_handler(self, signum, callback):
            callbacks[signum] = callback

        def remove_signal_handler(self, signum):
            removed.append(signum)
            return True

    async def blocking_scan(*_args, **_kwargs):
        callbacks[signal.SIGTERM]()
        await asyncio.sleep(0)
        raise AssertionError("cancelled scan continued")

    args = SimpleNamespace(input_file="targets.txt", output_dir=None, workers=None, timeout=30)

    async def exercise():
        with monkeypatch.context() as patch:
            patch.setattr(cli.asyncio, "get_running_loop", lambda: SignalLoop())
            patch.setattr(cli, "run_direct_scan", blocking_scan)
            await cli._run(args)

    with pytest.raises(asyncio.CancelledError):
        asyncio.run(exercise())
    assert removed == [signal.SIGINT, signal.SIGTERM]


def successful_result(tmp_path):
    return SimpleNamespace(
        canonical_path=tmp_path / "canonical.ndjson",
        generation_path=tmp_path / "generation",
        manifest_path=tmp_path / "manifest.json",
        resumed=True,
        status=RunStatus.COMPLETE,
    )


def test_main_prints_machine_readable_success_and_returns_zero(tmp_path, monkeypatch, capsys):
    result = successful_result(tmp_path)

    async def fake_run(_args):
        return result

    monkeypatch.setattr(cli, "_run", fake_run)

    assert cli.main(["targets.txt"]) == 0
    assert json.loads(capsys.readouterr().out) == {
        "canonical": str(result.canonical_path),
        "generation": str(result.generation_path),
        "manifest": str(result.manifest_path),
        "resumed": True,
        "status": "complete",
    }


@pytest.mark.parametrize("error_type", [KeyboardInterrupt, asyncio.CancelledError])
def test_main_maps_interruptions_to_shell_exit_130(error_type, monkeypatch, capsys):
    async def interrupted(_args):
        raise error_type

    monkeypatch.setattr(cli, "_run", interrupted)

    assert cli.main(["targets.txt"]) == 130
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "scan interrupted; durable state is resumable\n"


def test_main_sanitizes_failure_details_and_returns_one(monkeypatch, capsys):
    async def failed(_args):
        raise RuntimeError("secret backend details")

    monkeypatch.setattr(cli, "_run", failed)

    assert cli.main(["targets.txt"]) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "scan failed: RuntimeError\n"
    assert "secret backend details" not in captured.err


def test_python_module_entrypoint_exits_with_main_status(tmp_path, monkeypatch, capsys):
    result = successful_result(tmp_path)

    async def fake_direct_scan(*_args, **_kwargs):
        return result

    monkeypatch.setattr(direct_module, "run_direct_scan", fake_direct_scan)
    monkeypatch.setattr(sys, "argv", ["wappalyzer", "targets.txt"])

    with pytest.raises(SystemExit) as exit_info:
        runpy.run_path(str(Path(cli.__file__)), run_name="__main__")

    assert exit_info.value.code == 0
    assert json.loads(capsys.readouterr().out)["status"] == "complete"
