from wappalyzer import scanner


def test_automatic_http_workers_follow_cpu_allocation(monkeypatch):
    monkeypatch.delenv("WAPPALYZER_WORKERS", raising=False)
    monkeypatch.setattr(scanner, "_available_cpu_count", lambda: 12)

    assert scanner.automatic_worker_count("fast") == 12


def test_worker_environment_override(monkeypatch):
    monkeypatch.setenv("WAPPALYZER_WORKERS", "19")

    assert scanner.automatic_worker_count("full") == 19


def test_http_results_and_callbacks_follow_input_order(monkeypatch):
    def fake_job(url, scan_type, cookie, timeout):
        return url, {
            url: {
                "version": "",
                "confidence": 100,
                "categories": [],
                "groups": [],
            },
        }

    monkeypatch.setattr(scanner, "_http_scan_job", fake_job)
    callback_order = []

    with scanner.Wappalyzer(scan_type="fast", workers=1) as instance:
        result = instance.analyze_many(
            ["https://b.test", "https://a.test"],
            on_result=lambda url, technologies: callback_order.append(url),
        )

    assert list(result) == ["https://b.test", "https://a.test"]
    assert callback_order == ["https://b.test", "https://a.test"]
