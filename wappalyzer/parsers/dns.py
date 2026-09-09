import concurrent.futures

import dns.exception
import dns.resolver


def query(domain, record_type, timeout):
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout

    try:
        return [x.to_text() for x in resolver.resolve(domain, record_type)]
    except dns.exception.DNSException:
        return []


def get_dns(domain, timeout=5, workers=None):
    record_types = ["MX", "NS", "TXT", "SOA", "CNAME"]
    results = {}
    worker_count = min(
        len(record_types),
        max(1, workers if workers is not None else len(record_types)),
    )

    with concurrent.futures.ThreadPoolExecutor(max_workers=worker_count) as executor:
        future_to_record = {
            executor.submit(query, domain, record_type, timeout): record_type
            for record_type in record_types
        }
        for future in concurrent.futures.as_completed(future_to_record):
            record_type = future_to_record[future]

            try:
                results[record_type] = future.result()
            except Exception:
                results[record_type] = []

    return {record_type: results.get(record_type, []) for record_type in record_types}
