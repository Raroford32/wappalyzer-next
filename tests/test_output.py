from wappalyzer.core.utils import generate_html_report


def test_html_report_escapes_untrusted_values():
    report = generate_html_report(
        {
            "https://example.test/<script>alert(1)</script>": {
                "<img src=x onerror=alert(2)>": {
                    "version": "<script>alert(3)</script>",
                    "confidence": 100,
                    "categories": ["<svg onload=alert(4)>"],
                    "groups": ["Servers"],
                },
            },
        }
    )

    assert "<script>alert(1)</script>" not in report
    assert "<img src=x onerror=alert(2)>" not in report
    assert "<script>alert(3)</script>" not in report
    assert "<svg onload=alert(4)>" not in report
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in report
