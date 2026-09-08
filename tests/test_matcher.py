from wappalyzer.core.matcher import (
    compile_pattern,
    match,
    match_dict,
    single_match,
)


def test_compiled_patterns_are_reused():
    assert compile_pattern(r"Next\.js") is compile_pattern(r"Next\.js")


def test_numeric_version_wins_over_lexicographic_order():
    assert match(
        [r"v(9)\;version:\1", r"v(10)\;version:\1"],
        "v9 v10",
    ) == (True, "10", 100)


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


def test_invalid_regular_expression_is_a_non_match():
    assert single_match("[", "anything") == (False, "", 0)
