from wappalyzer.analyzers.js import match_js


def test_object_literal_guesses_are_not_treated_as_runtime_globals():
    evidence = [
        {
            "dict": {},
            "low_dict": {"ReactOnRails": False},
            "classes": [],
        }
    ]

    assert match_js({"ReactOnRails": ""}, evidence) == (False, "", 0)
