from bs4 import BeautifulSoup

from wappalyzer.analyzers.dom import compile_selector, match_dom


def soup(html):
    return BeautifulSoup(html, "html.parser")


def test_nested_attribute_rule_extracts_version():
    assert match_dom(
        {
            "[ng-version]": {
                "attributes": {
                    "ng-version": r"^([\d.]+)\;version:\1",
                },
            },
        },
        soup('<main ng-version="22.1.5"></main>'),
    ) == (True, "22.1.5", 100)


def test_nested_text_and_exists_rules():
    document = soup("<title>Central Authentication Service</title><astro-root></astro-root>")

    assert match_dom(
        {"title": {"text": "Central Authentication Service"}},
        document,
    )[0]
    assert match_dom(
        {"astro-root": {"exists": ""}},
        document,
    ) == (True, "", 100)


def test_nested_property_rule_reads_static_dom_properties():
    assert match_dom(
        {"div.example": {"properties": {"className": r"example"}}},
        soup('<div class="example"></div>'),
    )[0]


def test_missing_runtime_properties_and_sources_do_not_match():
    document = soup("<body><script></script></body>")

    assert match_dom(
        {"body": {"properties": {"__k": ""}}},
        document,
    ) == (False, "", 0)
    assert match_dom(
        {"script": {"src": ""}},
        document,
    ) == (False, "", 0)


def test_selector_compilation_is_reused():
    assert compile_selector("[data-app]") is compile_selector("[data-app]")


def test_invalid_selector_is_a_non_match():
    assert match_dom("div[", soup("<div></div>")) == (False, "", 0)


def test_repairable_upstream_selectors_remain_detectable():
    document = soup(
        """
        <a href="https://www.influxmarketing.com">
          <svg class="influx-footer-logo"></svg>
        </a>
        <script type="linguise/json"></script>
        """
    )

    assert match_dom(
        "a[href*='www.influxmarketing.com'] > svg[class*='influx-footer-logo'",
        document,
    )[0]
    assert match_dom("script[type='linguise/json]", document)[0]
