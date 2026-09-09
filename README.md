# Wappalyzer Next

This project is a command line tool and python library that uses the [Wappalyzer](https://www.wappalyzer.com/) browser extension and its fingerprints to detect technologies. Other projects that emerged after the discontinuation of the official open-source project are using outdated fingerprints and lack accuracy on dynamic web apps. This project bypasses those limitations by running the extension in Chromium through Playwright.

![demo](https://github.com/user-attachments/assets/7a51b034-c9a7-44e6-aa80-2f8a23311e72)

- [Installation](https://github.com/s0md3v/wappalyzer-next?tab=readme-ov-file#installation)
- [For Users](https://github.com/s0md3v/wappalyzer-next?tab=readme-ov-file#for-users)
- [For Developers](https://github.com/s0md3v/wappalyzer-next?tab=readme-ov-file#for-developers)
- [FAQ](https://github.com/s0md3v/wappalyzer-next?tab=readme-ov-file#faq)

## Installation

After installing the Python package, install Playwright's Chromium browser:

```bash
python -m playwright install chromium
```

In minimal Linux containers, install Chromium's system dependencies as well:

```bash
python -m playwright install-deps chromium
```


#### Install as a command-line tool
```bash
pipx install wappalyzer
pipx run --spec playwright playwright install chromium
```

#### Install as a library
To use it as a library, install it with `pip` inside an isolated container e.g. `venv` or `docker`. You may also `--break-system-packages` to do a 'regular' install but it is not recommended.

```bash
pip install wappalyzer
python -m playwright install chromium
```

#### Install with docker
<details><summary>Steps</summary>

1. Clone the repository:
```bash
git clone https://github.com/Raroford32/wappalyzer-next.git
cd wappalyzer-next
```

2. Build and run with Docker Compose:
```bash
docker compose build
```

3. Put one literal `IP:port` endpoint on each line of `targets.txt`, then run:

```bash
WAPPALYZER_UID="$(id -u)" WAPPALYZER_GID="$(id -g)" \
  docker compose run --rm wappalyzer targets.txt
```
</details>

## For Users
Use the scanner only on endpoints you own or are authorized to assess. The
command has one required operand: a UTF-8 text file containing literal
`IP:port` endpoints.

```text
# targets.txt
192.0.2.10:80
192.0.2.20:443
[2001:db8::10]:8443
```

```bash
wappalyzer targets.txt
```

The scanner fully ingests and fingerprints the file before network activity,
probes HTTP and HTTPS independently on every accepted port, and runs the
complete static plus browser evidence profile for every live protocol. It does
not infer the protocol from conventional port numbers and has no reduced
quality mode.

#### Input contract

- IPv4 uses `address:port`; IPv6 must use `[address]:port`.
- Ports are decimal integers from 1 through 65535.
- A UTF-8 BOM at the start and outer whitespace are accepted.
- Blank lines and lines whose first non-whitespace character is `#` are
  ignored and counted. Inline comments are invalid.
- Hostnames, URLs, CIDRs, user information, paths, queries, fragments, zone
  identifiers, ambiguous IPv4, invalid UTF-8, NUL bytes, and lines over 1 KiB
  are rejected without network activity.
- Duplicate endpoints share network work, but every physical non-ignored line
  receives its own ordered terminal record.

#### Options

- `--output-dir PATH`: immutable generation root. The default is
  `<input-file>.wappalyzer-runs` next to the input.
- `-w, --workers N`: maximum requested workers per stage. When omitted,
  effective CPU, memory, process, file-descriptor, and disk limits determine
  safe concurrency.
- `-t, --timeout SECONDS`: independent static-stage and browser-stage service
  budget. It never changes channel coverage or evidence limits.

#### Durable output and resume

On success, stdout contains one compact JSON object with `generation`,
`canonical`, `manifest`, `status`, `resumed`, and `accepted_endpoints`.
Diagnostic text goes to stderr. Each generation contains:

- `canonical.ndjson`: one schema-versioned record per non-ignored physical
  input line, in source order;
- `manifest.json`: immutable input, engine/fingerprint identities, reconciled
  counts, and the canonical file's byte count and SHA-256;
- `run.sqlite3`: the authoritative WAL-backed lifecycle, claim, result, and
  projection ledger;
- `generation.lock`: the kernel-locked ownership file.

Re-running the identical command after interruption automatically resumes a
compatible incomplete generation. Completed runs are immutable, so another
invocation creates a new generation. Changed input, engine semantics,
fingerprints, browser/runtime identity, or a live generation lock prevents
unsafe reuse.

Occurrence statuses are `invalid_input`, `unreachable`, `partial`,
`success_empty`, and `success`. A truncation, timeout, policy block, or failed
stage is always visible as `partial` or an indeterminate protocol outcome;
useful evidence is retained. `success_empty` means the complete observable
profile ran but matched no technology.

Exit codes are `0` for a completed run with at least one valid endpoint, `2`
for a completed run containing no valid endpoints, `1` for invocation,
state, output, or infrastructure failure, and `130` for interruption. An
interrupted run remains resumable.

## For Developers

The python library is available on pypi as `wappalyzer` and can be imported with the same name.

For development, install the checkout—not the published package:

```bash
python -m pip install --editable .
python -m playwright install chromium
python -m pip install pytest pytest-cov ruff
python -m pytest
```

#### Using the Library

Use `Wappalyzer` when scanning more than one URL. Worker processes or browsers are
started once, reused, and closed when the `with` block exits. Automatic worker
sizing uses the available CPU allocation for HTTP scans and both CPU and memory
budgets for full scans.

```python
from wappalyzer import Wappalyzer

with Wappalyzer(workers=None, timeout=30) as scanner:
    results = scanner.analyze_many(
        [
            "https://example.com",
            "https://github.com",
            "https://python.org",
        ]
    )

for url, technologies in results.items():
    print(url)
    for name, data in technologies.items():
        version = f" {data['version']}" if data["version"] else ""
        print(f"  {name}{version}")
```

The same scanner can also scan one URL at a time without reopening Chromium:

```python
from wappalyzer import Wappalyzer

with Wappalyzer(workers=3, timeout=30) as scanner:
    github = scanner.analyze("https://github.com")
    python = scanner.analyze("https://python.org")
```

For a single URL, `analyze()` is shorter. It creates its own scanner, runs one scan, and closes it.

```python
from wappalyzer import analyze

results = analyze(
    url="https://example.com",
    scan_type="full",  # 'fast', 'balanced', or 'full'
    cookie="sessionid=abc123",
    timeout=30,
)
```

Do not call the top-level `analyze()` function in a loop for large jobs. Use `Wappalyzer.analyze_many()` or `Wappalyzer.analyze()` on a reused scanner so Chromium and the Wappalyzer extension are not reloaded for every URL.

#### analyze() Function Parameters

- `url` (str): The URL to analyze
- `scan_type` (str, optional): Type of scan to perform
  - `'fast'`: Quick HTTP-based scan
  - `'balanced'`: HTTP-based scan with more requests
  - `'full'`: Complete scan including JavaScript execution (default)
- `workers` (int or `None`, optional): Worker count. `None` selects a
  resource-aware value (default).
- `cookie` (str, optional): Cookie header string for authenticated scans.
  Balanced scans never forward it to cross-origin assets.
- `timeout` (int, optional): Total HTTP request or browser page budget. When
  omitted, `WAPPALYZER_READ_TIMEOUT` is used.

#### Return Value

Returns a dictionary with the URL as key and detected technologies as value:

```json
{
  "https://github.com": {
    "Amazon S3": {
      "version": "",
      "confidence": 100,
      "categories": ["CDN"],
      "groups": ["Servers"]
    },
    "React Router": {
      "version": "6",
      "confidence": 100,
      "categories": ["JavaScript frameworks"],
      "groups": ["Web development"]
    }
  },
  "https://example.com": {}
}
```

Primary request failures raise `ScanRequestError` for one-URL calls. Batch calls
return an empty technology mapping for that URL and deliver the exception to
`on_error`; completed URLs continue streaming through `on_result`.

### FAQ

#### Why Chromium and Playwright?
The full scanner runs the Wappalyzer extension in Chromium through Playwright. Chromium extension support in Playwright is direct and does not require geckodriver or Selenium.

#### What is the difference between 'fast', 'balanced', and 'full' scan types?
These modes belong to the compatibility Python API. `fast` sends one HTTP
request, `balanced` adds bounded auxiliary static evidence, and `full` uses the
browser extension. The file CLI intentionally exposes no mode switch: it
always combines all static-only and browser-owned channels.

#### Can an IP-only scan identify every virtual host?
No. A literal IP and port cannot reveal hostname-routed sites or SNI names that
are absent from the input and from observable redirects. The scanner completely
processes the services reachable through the supplied literal endpoint; it does
not guess hostnames.

#### How are TLS failures and redirects handled?
HTTP and HTTPS are discovered separately. An untrusted certificate is reported
and scanned with an exception scoped to that exact HTTPS origin. Complete scans
follow bounded redirects needed for detection. Credentials are not inherited
from the host environment or forwarded across authorities. Redirects and
subresources to private, loopback, link-local, metadata, multicast, or
unspecified destinations are blocked unless the literal endpoint was supplied.

### Performance and isolation

- Direct-file scans use bounded discovery, static, isolated-regex, and browser
  workers; memory and queued work scale with selected concurrency rather than
  input length.
- CPU-bound fingerprint matching runs in replaceable spawned processes with
  wall-clock and resource limits.
- Fingerprint regular expressions and CSS selectors are compiled once per
  process.
- HTTP connections are bounded, TLS verification is scoped, response sizes are
  capped, and every network operation has a deadline.
- Browser workers pass an extension-readiness barrier before receiving work.
  Each protocol scan gets isolated page state, and unhealthy contexts are
  retired.
- Results commit as workers finish while the durable projector emits source
  order, so one slow early endpoint does not idle later workers.

The direct file CLI intentionally takes only `--workers`, `--timeout`, and
`--output-dir`; environment variables cannot reduce its evidence profile. The
following variables tune only the compatibility Python API:

| Variable | Default | Purpose |
| --- | --- | --- |
| `WAPPALYZER_WORKERS` | resource-aware | Override automatic top-level workers |
| `WAPPALYZER_ASSET_WORKERS` | global CPU budget | Explicit concurrent asset override |
| `WAPPALYZER_ASSET_LIMIT` | `64` | Maximum assets fetched per URL |
| `WAPPALYZER_MAX_ASSET_BYTES` | `2097152` | Maximum script, CSS, or probe body |
| `WAPPALYZER_CONNECT_TIMEOUT` | `5` | HTTP connect timeout in seconds |
| `WAPPALYZER_READ_TIMEOUT` | `30` | HTTP read timeout in seconds |
| `WAPPALYZER_MAX_RESPONSE_BYTES` | `10485760` | Maximum response body size |
| `WAPPALYZER_VERIFY_TLS` | `1` | Set to `0` only for explicitly trusted testing |
| `WAPPALYZER_BLOCK_RESOURCE_TYPES` | empty | Optional comma-separated browser resources to block; may reduce detection coverage |
