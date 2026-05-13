import re
from packaging.version import Version, InvalidVersion


def parse_version(v):
    try:
        return Version(str(v))
    except InvalidVersion:
        return None


def match_operator(cond, fact):
    op = cond.operator.lower()
    fact_value = fact.value
    cond_value = cond.value

    if op == "exists":
        return 1.0

    if op == "eq":
        return 1.0 if str(fact_value).lower() == str(cond_value).lower() else 0.0

    if op == "contains":
        return 1.0 if str(cond_value).lower() in str(fact_value).lower() else 0.0

    if op == "regex":
        pattern = cond.pattern or str(cond_value)
        return 1.0 if re.search(pattern, str(fact_value)) else 0.0

    if op in ["lt", "lte", "gt", "gte"]:
        left = parse_version(fact_value)
        right = parse_version(cond_value)

        if left is None or right is None:
            return 0.0

        if op == "lt":
            return 1.0 if left < right else 0.0
        if op == "lte":
            return 1.0 if left <= right else 0.0
        if op == "gt":
            return 1.0 if left > right else 0.0
        if op == "gte":
            return 1.0 if left >= right else 0.0

    return 0.0