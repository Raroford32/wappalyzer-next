from wappalyzer.core.matcher import better_match, match_dict


def fix_keys(pattern, js, classes):
    new_js = js.copy()
    for key, value in pattern.items():
        if "." in key:
            for k, v in js.items():
                if k in key and all([c in classes for c in key.split(".")]):
                    new_js[key] = new_js.pop(k)
                    break
    for k, v in js.items():
        if len(k) <= 2 and k in new_js and not v:
            new_js.pop(k)
    return new_js


def match_js(pattern, js):
    best = (False, "", 0)

    for js_dict in js:
        js, low_js, classes = js_dict["dict"], js_dict["low_dict"], js_dict["classes"]
        js = fix_keys(pattern, js, classes)
        low_js = fix_keys(pattern, low_js, classes)
        for key in low_js.copy().keys():
            if key in js:
                del low_js[key]
        best = better_match(match_dict(pattern, js), best)
        best = better_match(match_dict(pattern, low_js), best)

    return best
