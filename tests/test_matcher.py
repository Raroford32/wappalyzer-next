from wappalyzer.core.matcher import (
    better_version,
    compile_pattern,
    match,
    match_dict,
    normalize_version,
    single_match,
)


def test_compiled_patterns_are_reused():
    assert compile_pattern(r"Next\.js") is compile_pattern(r"Next\.js")


def test_numeric_version_wins_over_lexicographic_order():
    assert match(
        [r"v(9)\;version:\1", r"v(10)\;version:\1"],
        "v9 v10",
    ) == (True, "10", 100)


def test_version_selection_is_order_independent():
    assert better_version("9", "10") == "10"
    assert better_version("10", "9") == "10"
    assert better_version("", "10") == "10"


def test_conditional_version_expansion():
    matched, version, confidence = single_match(
        r"lib(?:-([a-z]+))?\;version:\1?preview:stable",
        "lib-preview",
    )

    assert matched
    assert version == "preview"
    assert confidence == 100


def test_dictionary_matching_can_ignore_key_case():
    assert match_dict(
        {"x-powered-by": r"Next\.js"},
        {"X-Powered-By": "Next.js"},
        case_insensitive_keys=True,
    ) == (True, "", 100)


def test_patterns_are_case_insensitive_like_the_extension():
    assert single_match("hono", "HONO") == (True, "", 100)


def test_distinct_matching_patterns_add_confidence_once_each():
    patterns = [
        r"video-js\;confidence:25",
        r"vjs-tech\;confidence:75",
    ]

    assert match(patterns, ["video-js", "video-js vjs-tech"]) == (True, "", 100)


def test_versions_use_upstream_character_and_size_bounds():
    assert normalize_version("3.45") == "3.45"
    assert normalize_version("API v3.45") == ""
    assert normalize_version("1234567890123456") == ""
    assert normalize_version("10000") == ""


def test_invalid_regular_expression_is_a_non_match():
    assert single_match("[", "anything") == (False, "", 0)


def test_javascript_identity_escapes_and_character_ranges_are_supported():
    assert single_match(r"\keyreply\.com", "keyreply.com")[0]
    assert single_match(
        r"v([\d\.-\w]+)\;version:\1",
        "v4.12-beta",
    ) == (True, "4.12-beta", 100)
