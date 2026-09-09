from wappalyzer.parsers import dns


def test_dns_nested_concurrency_respects_supplied_worker_budget(monkeypatch):
    created = []
    real_executor = dns.concurrent.futures.ThreadPoolExecutor

    def executor(*args, **kwargs):
        created.append(kwargs["max_workers"])
        return real_executor(*args, **kwargs)

    monkeypatch.setattr(dns.concurrent.futures, "ThreadPoolExecutor", executor)
    monkeypatch.setattr(
        dns,
        "query",
        lambda domain, record_type, timeout: [f"{domain}:{record_type}"],
    )

    result = dns.get_dns("example.test", workers=2)

    assert created == [2]
    assert list(result) == ["MX", "NS", "TXT", "SOA", "CNAME"]
