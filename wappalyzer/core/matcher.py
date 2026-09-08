import functools
import re

"""
Special strings: version, confidence

\\;confidence:50
jquery-([0-9.]+).js\\;version:\\1

\\1      Returns the first match.
\\1?a:   Returns a if the first match contains a value, nothing otherwise.
\\1?a:b  Returns a if the first match contains a value, b otherwise.
\\1?:b   Returns nothing if the first match contains a value, b otherwise.
foo\\1   Returns foo with the first match appended.
"""


def group_or_literal(option, match):
    def replace_group(group_match):
        try:
            return match.group(int(group_match.group(1))) or ""
        except (IndexError, ValueError):
            return ""

    return re.sub(r"\\(\d+)", replace_group, option)


def get_version(match, version_type):
    version = ""
    if version_type == "":
        return version
    if "?:" in version_type:  # \\1?:b
        condition, fallback = version_type.split("?:", 1)
        if not group_or_literal(condition, match):
            version = group_or_literal(fallback, match)
    elif "?" in version_type and ":" in version_type:  # \\1?a:b or \\1?a:
        condition, choices = version_type.split("?", 1)
        truthy, falsy = choices.split(":", 1)
        version = group_or_literal(
            truthy if group_or_literal(condition, match) else falsy,
            match,
        )
    else:
        version = group_or_literal(version_type, match)
    if version:
        version = re.split(r"[\)\]\},]", version.replace("'", "").replace('"', ""))[0]
    return version


def normalize_match_value(value):
    if isinstance(value, bool):
        return str(value).lower()
    if value is None:
        return ""
    return str(value)


def parse_pattern(regex):
    regex = normalize_match_value(regex)
    confidence = 100
    clean_regex = regex
    if "\\;confidence:" in clean_regex:
        this_match = re.search(r"\\;confidence:(\d+)", regex)
        confidence = int(this_match.group(1).strip())
        clean_regex = clean_regex.replace(this_match.group(0), "")
    version_type = ""
    if "\\;version:" in clean_regex:
        version_type = clean_regex.split("\\;version:")[1]
        clean_regex = clean_regex.split("\\;version:")[0]
    return clean_regex, version_type, confidence


@functools.cache
def compile_pattern(regex):
    clean_regex, version_type, confidence = parse_pattern(regex)

    try:
        return re.compile(clean_regex), version_type, confidence
    except re.error:
        repaired_regex = repair_javascript_pattern(clean_regex)

        try:
            return re.compile(repaired_regex), version_type, confidence
        except re.error:
            return None, version_type, confidence


def repair_javascript_pattern(regex):
    valid_letter_escapes = set("AbBdDsSwWZfnrtvaxuUN")

    def replace_escape(match):
        character = match.group(1)
        return match.group(0) if character in valid_letter_escapes else character

    regex = re.sub(r"\\([A-Za-z])", replace_escape, regex)
    return regex.replace(r"\.-", r"\.\-")


def version_key(version):
    parts = []

    for part in re.split(r"(\d+)", version or ""):
        if not part:
            continue

        if part.isdigit():
            parts.append((1, int(part)))
        else:
            parts.append((0, part.casefold()))

    return tuple(parts)


def version_rank(version):
    normalized = version or ""
    return (
        version_key(normalized),
        len(normalized),
        normalized.casefold(),
        normalized,
    )


def better_version(candidate, current):
    if not candidate:
        return current or ""

    if not current:
        return candidate

    return candidate if version_rank(candidate) > version_rank(current) else current


def match_key(matched, version, confidence):
    return (
        bool(matched),
        int(confidence),
        bool(version),
        version_rank(version),
    )


def better_match(candidate, current):
    return candidate if match_key(*candidate) > match_key(*current) else current


def single_match(regex, string):
    compiled, version_type, confidence = compile_pattern(regex)

    if compiled is None:
        return False, "", 0

    this_match = compiled.search(normalize_match_value(string))
    if this_match:
        return True, get_version(this_match, version_type), confidence
    return False, "", 0


def match(regex, string):
    if isinstance(string, (list, tuple, set)):
        to_match = string
    else:
        to_match = [string]
    best = (False, "", 0)

    for s in to_match:
        if not isinstance(s, str):
            s = normalize_match_value(s)
        regexes = [regex] if isinstance(regex, str) else regex
        for r in regexes:
            best = better_match(single_match(r, s), best)

    return best


def match_dict(pattern_dict, response_dict, case_insensitive_keys=False):
    if case_insensitive_keys:
        response_dict = {
            normalize_match_value(key).casefold(): value for key, value in response_dict.items()
        }

    best = (False, "", 0)

    for name, pattern in pattern_dict.items():
        if case_insensitive_keys:
            name = normalize_match_value(name).casefold()

        if name in response_dict:
            values = response_dict[name]
            if not isinstance(values, list):
                values = [values]
            for value in values:
                if pattern == "":
                    best = better_match((True, "", 100), best)
                else:
                    best = better_match(match(pattern, value), best)

    return best
