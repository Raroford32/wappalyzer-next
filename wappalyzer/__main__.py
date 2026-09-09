import argparse
import asyncio
import json
import signal
import sys

from wappalyzer.direct import run_direct_scan


def positive_int(value):
    try:
        number = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{value!r} is not an integer")

    if number < 1:
        raise argparse.ArgumentTypeError("value must be at least 1")

    return number


def build_parser():
    parser = argparse.ArgumentParser(
        prog="wappalyzer",
        description=(
            "Scan every IP:port occurrence in a UTF-8 target file with the "
            "durable complete detection engine."
        ),
    )
    parser.add_argument(
        "input_file",
        help="UTF-8 text file containing one IP:port endpoint per line",
    )
    parser.add_argument(
        "--output-dir",
        help="generation root (default: <input>.wappalyzer-runs)",
    )
    parser.add_argument(
        "-w",
        "--workers",
        help="maximum requested workers per stage (default: automatic)",
        default=None,
        type=positive_int,
    )
    parser.add_argument(
        "-t",
        "--timeout",
        help="independent static and browser service timeout in seconds",
        default=30,
        type=positive_int,
    )
    return parser


async def _run(args):
    task = asyncio.current_task()
    loop = asyncio.get_running_loop()
    installed_signals = []
    for signum in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(signum, task.cancel)
        except (NotImplementedError, RuntimeError):
            continue
        installed_signals.append(signum)
    try:
        return await run_direct_scan(
            args.input_file,
            output_root=args.output_dir,
            workers=args.workers,
            timeout=args.timeout,
        )
    finally:
        for signum in installed_signals:
            loop.remove_signal_handler(signum)


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        result = asyncio.run(_run(args))
    except (KeyboardInterrupt, asyncio.CancelledError):
        print("scan interrupted; durable state is resumable", file=sys.stderr)
        return 130
    except Exception as error:
        print(f"scan failed: {type(error).__name__}", file=sys.stderr)
        return 1

    print(
        json.dumps(
            {
                "canonical": str(result.canonical_path),
                "generation": str(result.generation_path),
                "manifest": str(result.manifest_path),
                "resumed": result.resumed,
                "status": result.status.value,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
