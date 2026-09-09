import functools

import soupsieve

from wappalyzer.core.matcher import (
    better_match,
    combine_matches,
    match,
    parse_pattern,
)

STATIC_PROPERTIES = {
    "className",
    "html",
    "innerHTML",
    "innerText",
    "tagName",
    "text",
    "textContent",
}


@functools.cache
def compile_selector(selector):
    try:
        return soupsieve.compile(selector)
    except Exception:
        repaired_selector = repair_selector(selector)

        try:
            return soupsieve.compile(repaired_selector)
        except Exception:
            return None


def repair_selector(selector):
    repaired = selector

    if repaired.endswith("]"):
        if repaired.count("'") % 2:
            repaired = f"{repaired[:-1]}']"
        elif repaired.count('"') % 2:
            repaired = f'{repaired[:-1]}"]'

    missing_brackets = repaired.count("[") - repaired.count("]")

    if missing_brackets > 0:
        repaired += "]" * missing_brackets

    return repaired


def query(soup, selector):
    compiled = compile_selector(selector)

    if compiled is None:
        return []

    return compiled.select(soup)


def element_property(element, property_name):
    if property_name not in STATIC_PROPERTIES:
        return None

    if property_name in ("innerText", "text", "textContent"):
        return element.get_text(" ", strip=True)

    if property_name in ("innerHTML", "html"):
        return element.decode_contents()

    if property_name == "tagName":
        return element.name.upper()

    if property_name == "className":
        value = element.get("class", [])
        return " ".join(value) if isinstance(value, list) else value

    return None


def match_element_rule(element, rule):
    aggregate = (False, "", 0)

    if not isinstance(rule, dict):
        return match(rule, element.get_text(" ", strip=True))

    if "exists" in rule:
        exists_pattern = rule["exists"]
        candidate = (
            (True, "", 100)
            if exists_pattern == ""
            else match(exists_pattern, element.get_text(" ", strip=True))
        )
        aggregate = combine_matches(aggregate, candidate)

    if "text" in rule:
        text = element.get_text(" ", strip=True)

        if text:
            aggregate = combine_matches(aggregate, match(rule["text"], text))

    attributes = rule.get("attributes", {})
    if isinstance(attributes, dict):
        for name, pattern in attributes.items():
            if not element.has_attr(name):
                continue

            value = element.get(name, "")
            if isinstance(value, list):
                value = " ".join(value)

            candidate = (True, "", 100) if pattern == "" else match(pattern, value)
            aggregate = combine_matches(aggregate, candidate)

    properties = rule.get("properties", {})
    if isinstance(properties, dict):
        for name, pattern in properties.items():
            value = element_property(element, name)

            if value is None:
                continue

            candidate = (True, "", 100) if pattern == "" else match(pattern, value)
            aggregate = combine_matches(aggregate, candidate)

    if "src" in rule:
        source = element.get("src") or element.get("href", "")

        if source:
            candidate = (True, "", 100) if rule["src"] == "" else match(rule["src"], source)
            aggregate = combine_matches(aggregate, candidate)

    return aggregate


def match_dom(selectors, soup):
    if isinstance(selectors, str):
        clean_selector, version_type, confidence = parse_pattern(selectors)
        return (True, "", confidence) if query(soup, clean_selector) else (False, "", 0)

    if isinstance(selectors, list):
        aggregate = (False, "", 0)

        for selector in selectors:
            clean_selector, version_type, confidence = parse_pattern(selector)
            if query(soup, clean_selector):
                aggregate = combine_matches(aggregate, (True, "", confidence))

        return aggregate

    if isinstance(selectors, dict):
        aggregate = (False, "", 0)

        for selector, rule in selectors.items():
            clean_selector, _, selector_confidence = parse_pattern(selector)
            selector_match = (False, "", 0)

            for element in query(soup, clean_selector):
                candidate = match_element_rule(element, rule)

                if candidate[0] and candidate[2] == 100:
                    candidate = (candidate[0], candidate[1], selector_confidence)

                selector_match = better_match(candidate, selector_match)

            aggregate = combine_matches(aggregate, selector_match)

        return aggregate

    return False, "", 0
