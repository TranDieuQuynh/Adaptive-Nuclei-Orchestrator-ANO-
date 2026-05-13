from copy import deepcopy

import yaml


_SIGNATURE_DB = {
    "path": None,
    "templates": [],
    "nuclei": {},
}
_SIGNATURE_INDEX = {}


def load_signature_db(path):
    global _SIGNATURE_DB, _SIGNATURE_INDEX

    with open(path, "r", encoding="utf-8") as file:
        data = yaml.safe_load(file) or {}

    templates = data.get("templates", [])
    _SIGNATURE_DB = {
        "path": path,
        "templates": templates,
        "nuclei": data.get("nuclei", {}),
    }
    _SIGNATURE_INDEX = {
        template.get("id"): template
        for template in templates
        if template.get("id")
    }
    return deepcopy(_SIGNATURE_DB)


def get_signature_by_id(signature_id):
    signature = _SIGNATURE_INDEX.get(signature_id)
    if signature is None:
        return None
    return deepcopy(signature)


def find_by_protocol(protocol):
    expected = str(protocol).strip().lower()
    return [
        deepcopy(template)
        for template in _SIGNATURE_DB["templates"]
        if str(template.get("protocol") or "").strip().lower() == expected
    ]


def find_by_tags(tags):
    expected_tags = {
        str(tag).strip().lower()
        for tag in _ensure_list(tags)
        if str(tag).strip()
    }

    if not expected_tags:
        return []

    results = []
    for template in _SIGNATURE_DB["templates"]:
        template_tags = {
            str(tag).strip().lower()
            for tag in template.get("tags", [])
            if str(tag).strip()
        }
        if expected_tags.issubset(template_tags):
            results.append(deepcopy(template))

    return results


def find_by_inputs(facts):
    return [
        deepcopy(template)
        for template in _SIGNATURE_DB["templates"]
        if _conditions_match(template.get("input", []), facts)
    ]


def find_runnable_signatures(facts):
    return [
        deepcopy(template)
        for template in _SIGNATURE_DB["templates"]
        if _conditions_match(_merge_conditions(template), facts)
    ]


def _merge_conditions(template):
    merged = []
    seen = set()

    for field in ("input", "precondition"):
        for condition in template.get(field, []):
            normalized = _normalize_condition(condition)
            if normalized in seen:
                continue
            seen.add(normalized)
            merged.append(condition)

    return merged


def _conditions_match(conditions, facts):
    for condition in conditions:
        if not _fact_exists(condition, facts):
            return False
    return True


def _fact_exists(condition, facts):
    fact_type, fact_value = _normalize_condition(condition)

    for fact in facts:
        if fact.get("type") != fact_type:
            continue

        if fact_value is None:
            return True

        if str(fact.get("value")) == fact_value:
            return True

    return False


def _normalize_condition(condition):
    if isinstance(condition, dict):
        if len(condition) != 1:
            raise ValueError(f"Unsupported condition format: {condition!r}")
        key, value = next(iter(condition.items()))
        return str(key).strip(), str(value).strip()

    if not isinstance(condition, str):
        raise TypeError(
            f"Condition must be str or single-item dict, got {type(condition)!r}"
        )

    condition = condition.strip()
    if "=" in condition:
        key, value = condition.split("=", 1)
        return key.strip(), value.strip()
    return condition, None


def _ensure_list(value):
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]
