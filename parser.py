import json
import re
from urllib.parse import urlparse

from confidence_model import resolve_template_prior, score_fact_confidence


FACT_TYPE_ALIASES = {
    "url": "url",
    "domain": "domain",
    "host": "domain",
    "ip": "ip",
    "port": "port",
    "protocol": "protocol",
    "service": "service",
    "title": "title",
    "path": "path",
    "header": "header",
    "technology": "software_product",
    "product": "software_product",
    "software_product": "software_product",
    "software-product": "software_product",
    "software version": "software_version",
    "software-version": "software_version",
    "software_version": "software_version",
    "version": "software_version",
    "vendor": "vendor",
    "framework": "framework",
    "cms": "cms",
    "plugin": "plugin",
    "wordpress-plugin": "plugin",
    "wordpress-theme": "plugin",
    "php-version": "software_version",
    "django-version": "software_version",
    "drupal-version": "software_version",
    "grafana-version": "software_version",
    "phpinfo-page": "path",
    "config-json-file": "path",
    "wordpress-hidden-login": "path",
    "vulnerability": "vulnerability",
}

LOWERCASE_VALUE_TYPES = {
    "software_product",
    "software_version",
    "vendor",
    "framework",
    "cms",
    "plugin",
    "service",
    "protocol",
    "reachability",
}

FACT_KEYWORD_DICTIONARY = {
    "wordpress": ("software_product", "wordpress"),
    "drupal": ("software_product", "drupal"),
    "django": ("software_product", "django"),
    "magento": ("software_product", "magento"),
    "moodle": ("software_product", "moodle"),
    "apache": ("software_product", "apache"),
    "nginx": ("software_product", "nginx"),
    "php": ("software_product", "php"),
    "grafana": ("software_product", "grafana"),
    "gitlab": ("software_product", "gitlab"),
    "apache-coyote": ("software_product", "tomcat"),
}

FACT_REGEX_PATTERNS = {
    "ip": re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b"),
    "software_version": re.compile(r"\b\d+(?:\.\d+)+\b"),
}

FACT_KEY_BY_TYPE = {
    "software_product": "name",
    "software_version": "number",
    "vendor": "name",
    "framework": "name",
    "cms": "name",
    "plugin": "name",
    "service": "name",
    "title": "text",
    "header": "name",
    "path": "path",
    "url": "url",
    "domain": "host",
    "ip": "address",
    "port": "number",
    "protocol": "name",
    "vulnerability": "id",
}

PRODUCT_ALIAS_PATTERNS = (
    (re.compile(r"\bapache[-\s_]*tomcat\b", re.IGNORECASE), "tomcat"),
    (re.compile(r"\bapache[-\s_]*coyote\b", re.IGNORECASE), "tomcat"),
    (re.compile(r"\btomcat\b", re.IGNORECASE), "tomcat"),
    (re.compile(r"\bapache[-\s_]*http[-\s_]*server\b", re.IGNORECASE), "apache"),
)

PRODUCT_ALIASES = {
    "apache tomcat": "tomcat",
    "apache-tomcat": "tomcat",
    "apache_tomcat": "tomcat",
    "tomcat": "tomcat",
    "apache coyote": "tomcat",
    "apache-coyote": "tomcat",
}

VENDOR_ALIAS_MAP = {
    "apache software foundation": "apache",
    "apache foundation": "apache",
    "apache": "apache",
    "microsoft corporation": "microsoft",
    "oracle corporation": "oracle",
}

VENDOR_ALIASES = {
    "apache software foundation": "apache",
    "apache foundation": "apache",
    "apache": "apache",
    "ms": "microsoft",
    "microsoft corporation": "microsoft",
    "oracle corporation": "oracle",
}

SERVICE_ALIASES = {
    "www": "http",
    "www-http": "http",
    "http-alt": "http",
    "https-alt": "https",
    "ssl/http": "https",
    "ssl-http": "https",
}

PROTOCOL_ALIASES = {
    "http": "http",
    "https": "http",
    "http/1.1": "http",
    "http/2": "http",
    "h2": "http",
    "ws": "websocket",
    "wss": "websocket",
    "web-socket": "websocket",
    "tcp": "tcp",
    "udp": "udp",
}

HEADER_ALIASES = {
    "x_powered_by": "x-powered-by",
    "x-powered-by": "x-powered-by",
    "x_generator": "x-generator",
    "x-generator": "x-generator",
    "server": "server",
}

PATH_ALIASES = {
    "/admin/": "/admin",
    "/login/": "/login",
    "/wp-login": "/wp-login.php",
    "/index.php/": "/index.php",
}


def normalize_alias_token(value):
    text = str(value or "").strip().lower()
    if not text:
        return ""

    text = text.replace("_", "-")
    text = re.sub(r"\s+", "-", text)
    text = re.sub(r"-{2,}", "-", text).strip("-")
    return text


def normalize_header_feature(value):
    text = str(value or "").strip().lower()
    if not text:
        return ""

    header_name = text.split(":", 1)[0].strip()
    if "apache-coyote" in header_name:
        return "apache-coyote"
    alias_key = normalize_alias_token(header_name)
    return HEADER_ALIASES.get(alias_key, alias_key)


def normalize_path_feature(value):
    text = str(value or "").strip()
    if not text:
        return ""

    if "://" in text:
        parsed = urlparse(text)
        text = parsed.path or "/"

    lowered = text.split("?", 1)[0].split("#", 1)[0].strip().lower()
    if not lowered:
        return ""

    if not lowered.startswith("/"):
        lowered = "/" + lowered

    if len(lowered) > 1 and lowered.endswith("/"):
        lowered = lowered[:-1]

    if lowered + "/" in PATH_ALIASES:
        return PATH_ALIASES[lowered + "/"]

    lowered = PATH_ALIASES.get(lowered, lowered)

    return lowered


def normalize_product_fact_value(raw_value):
    text = str(raw_value or "").strip().lower()
    if not text:
        return ""

    compact = re.sub(r"[\s_\-]+", " ", text)
    compact = re.sub(r"\bversion\s*[:=]?\s*\d+(?:\.\d+)*\b", "", compact)
    compact = re.sub(r"\bv?\d+(?:\.\d+)+(?:[-_a-z0-9]+)?\b", "", compact)
    compact = compact.strip(" -_/.,")

    alias_key = normalize_alias_token(compact)
    if alias_key in PRODUCT_ALIASES:
        return PRODUCT_ALIASES[alias_key]

    for pattern, canonical in PRODUCT_ALIAS_PATTERNS:
        if pattern.search(compact):
            return canonical

    return compact


def normalize_vendor_fact_value(raw_value):
    text = str(raw_value or "").strip().lower()
    if not text:
        return ""

    compact = re.sub(r"[\s_\-]+", " ", text).strip()
    normalized_token = normalize_alias_token(compact)
    return VENDOR_ALIASES.get(compact, VENDOR_ALIASES.get(normalized_token, VENDOR_ALIAS_MAP.get(compact, compact)))


def normalize_service_fact_value(raw_value):
    text = str(raw_value or "").strip().lower()
    if not text:
        return ""

    if ":" in text:
        service_name, suffix = text.split(":", 1)
        normalized_name = SERVICE_ALIASES.get(
            normalize_alias_token(service_name),
            normalize_alias_token(service_name),
        )
        return f"{normalized_name}:{suffix.strip()}"

    normalized_token = normalize_alias_token(text)
    return SERVICE_ALIASES.get(normalized_token, normalized_token)


def normalize_protocol_fact_value(raw_value):
    text = str(raw_value or "").strip().lower()
    if not text:
        return ""

    normalized_token = normalize_alias_token(text)
    return PROTOCOL_ALIASES.get(normalized_token, normalized_token)


def infer_fact_key_name(fact_type):
    canonical_type = canonicalize_fact_type(fact_type)
    return FACT_KEY_BY_TYPE.get(canonical_type, "value")


def fact_type_label(fact_type):
    canonical_type = canonicalize_fact_type(fact_type)
    if canonical_type == "software_product":
        return "product"
    if canonical_type == "software_version":
        return "version"
    return canonical_type


def canonicalize_fact_type(raw_fact_type):
    text = str(raw_fact_type or "").strip()
    if not text:
        return ""

    lowered = text.lower().replace("_", "-").replace(" ", "-")
    return FACT_TYPE_ALIASES.get(lowered, lowered.replace("-", "_"))


def canonicalize_fact_value(fact_type, raw_value):
    text = str(raw_value or "").strip()
    if not text:
        return ""

    canonical_type = canonicalize_fact_type(fact_type)
    if canonical_type == "software_product":
        return normalize_product_fact_value(text)
    if canonical_type == "vendor":
        return normalize_vendor_fact_value(text)
    if canonical_type == "service":
        return normalize_service_fact_value(text)
    if canonical_type == "protocol":
        return normalize_protocol_fact_value(text)
    if canonical_type == "header":
        return normalize_header_feature(text)
    if canonical_type == "path":
        return normalize_path_feature(text)
    if canonical_type in LOWERCASE_VALUE_TYPES:
        return text.lower()
    return text


def infer_dictionary_regex_facts(text, source, evidence=None, template_prior=None):
    lowered_text = str(text or "").strip().lower()
    if not lowered_text:
        return []

    inferred = []

    for keyword, (fact_type, fact_value) in FACT_KEYWORD_DICTIONARY.items():
        if keyword in lowered_text:
            built = build_fact(
                fact_type,
                fact_value,
                source,
                None,
                evidence=evidence or text,
                method="inferred-dictionary",
                template_prior=template_prior,
            )
            if built is not None:
                inferred.append(built)

    for fact_type, pattern in FACT_REGEX_PATTERNS.items():
        for match in pattern.findall(str(text)):
            built = build_fact(
                fact_type,
                match,
                source,
                None,
                evidence=evidence or text,
                method="inferred-regex",
                template_prior=template_prior,
            )
            if built is not None:
                inferred.append(built)

    return inferred


def normalize_output_spec(condition):
    if isinstance(condition, dict):
        if len(condition) != 1:
            raise ValueError(f"Unsupported output format: {condition!r}")
        key, value = next(iter(condition.items()))
        return str(key).strip(), str(value).strip()

    if not isinstance(condition, str):
        raise TypeError(
            f"Output spec must be str or single-item dict, got {type(condition)!r}"
        )

    condition = condition.strip()
    if "=" in condition:
        key, value = condition.split("=", 1)
        return (
            canonicalize_fact_type(key.strip()),
            canonicalize_fact_value(key.strip(), value.strip()),
        )
    return canonicalize_fact_type(condition), None


def parse_nuclei_results(results, template):
    if isinstance(results, str):
        results = parse_json_lines(results)

    if not results:
        return []

    facts = []
    template_id = template.get("id", "unknown-template")
    template_prior = to_confidence_score(template.get("confidence"))
    declared_outputs = template.get("output", [])

    for result in results:
        if not isinstance(result, dict):
            continue

        for output_spec in declared_outputs:
            facts.extend(
                build_facts_from_output_spec(
                    output_spec=output_spec,
                    result=result,
                    template_id=template_id,
                    template_prior=template_prior,
                )
            )

        if not declared_outputs:
            facts.extend(
                build_heuristic_facts(
                    result=result,
                    template_id=template_id,
                    template_prior=template_prior,
                )
            )

    return deduplicate_facts(facts)


def build_facts_from_output_spec(output_spec, result, template_id, template_prior):
    fact_type, fact_value = normalize_output_spec(output_spec)
    evidence = get_best_match_location(result) or output_spec
    extracted_count = len(get_extracted_results(result))

    if fact_value is not None:
        facts = []
        built = build_fact(
            fact_type,
            fact_value,
            template_id,
            None,
            evidence=evidence,
            method="template-output",
            template_prior=template_prior,
            extracted_count=extracted_count,
        )
        if built is not None:
            facts.append(built)
        facts.extend(
            infer_dictionary_regex_facts(
                text=fact_value,
                source=template_id,
                evidence=evidence,
                template_prior=template_prior,
            )
        )
        return facts

    if not output_matches_result(fact_type, result):
        return []

    candidate_values = infer_output_values(fact_type, result, template_id)
    facts = []
    for value in candidate_values:
        built = build_fact(
            fact_type,
            value,
            template_id,
            None,
            evidence=evidence,
            method="template-output",
            template_prior=template_prior,
            extracted_count=extracted_count,
        )
        if built is not None:
            facts.append(built)
    for value in candidate_values:
        facts.extend(
            infer_dictionary_regex_facts(
                text=value,
                source=template_id,
                evidence=evidence,
                template_prior=template_prior,
            )
        )
    return facts


def infer_output_values(fact_type, result, template_id):
    extracted = get_extracted_results(result)
    matched_at = get_best_match_location(result)
    info = result.get("info") or {}
    meta = result.get("meta") or {}

    lower_type = fact_type.lower()

    if lower_type == "url":
        return compact_values([matched_at, result.get("host"), result.get("matched-at")])

    if "version" in lower_type:
        if extracted:
            return extracted
        return compact_values([meta.get("version")])

    if "panel" in lower_type or "login" in lower_type:
        return compact_values([extract_path(matched_at) or matched_at])

    if "page" in lower_type or "file" in lower_type:
        return compact_values([extract_path(matched_at) or matched_at])

    if "plugin" in lower_type or "theme" in lower_type:
        return extracted

    if "vulnerability" in lower_type:
        severity = (info.get("severity") or "").strip()
        vuln_name = (
            info.get("name")
            or result.get("template-id")
            or template_id
        )
        if severity:
            return [f"{vuln_name} ({severity})"]
        return [vuln_name]

    if extracted:
        return extracted

    return compact_values([extract_path(matched_at), matched_at, result.get("host")])


def build_heuristic_facts(result, template_id, template_prior):
    info = result.get("info") or {}
    severity = (info.get("severity") or "").strip()
    info_name = info.get("name") or result.get("template-id") or template_id
    matched_at = get_best_match_location(result)
    extracted = get_extracted_results(result)

    heuristic_facts = []

    # Derive endpoint-level facts from successful matches even when a template has
    # no explicit output mapping in the normalized signature database.
    matched_path = extract_path(matched_at)
    if matched_path:
        built_path = build_fact(
            "path",
            matched_path,
            template_id,
            None,
            evidence=matched_at,
            method="heuristic-output",
            template_prior=template_prior,
            extracted_count=len(extracted),
        )
        if built_path is not None:
            heuristic_facts.append(built_path)

    for text in [
        result.get("template-id"),
        info_name,
        result.get("matcher-name"),
        result.get("extractor-name"),
        *extracted,
    ]:
        heuristic_facts.extend(
            infer_dictionary_regex_facts(
                text=text,
                source=template_id,
                evidence=matched_at or info_name,
                template_prior=template_prior,
            )
        )

    if severity and severity.lower() != "info":
        vulnerability_fact = build_fact(
            "Vulnerability",
            f"{info_name} ({severity})",
            template_id,
            None,
            evidence=matched_at or info_name,
            method="template-output",
            template_prior=template_prior,
            extracted_count=len(extracted),
        )
        if vulnerability_fact is not None:
            heuristic_facts.append(vulnerability_fact)

    # Fallback for info templates that matched but do not provide extracted values:
    # keep a stable finding so orchestration can accumulate evidence from URL scans.
    if not heuristic_facts:
        finding = build_fact(
            "vulnerability",
            str(result.get("template-id") or template_id),
            template_id,
            None,
            evidence=matched_at or info_name,
            method="heuristic-output",
            template_prior=template_prior,
            extracted_count=len(extracted),
        )
        if finding is not None:
            heuristic_facts.append(finding)

    return deduplicate_facts(heuristic_facts)


def build_fact(
    fact_type,
    value,
    source,
    confidence,
    evidence=None,
    method="direct",
    template_prior=None,
    extracted_count=0,
):
    canonical_type = canonicalize_fact_type(fact_type)
    canonical_value = canonicalize_fact_value(canonical_type, value)
    if not canonical_type or not canonical_value:
        return None
    fact = {
        "type": canonical_type,
        "type_label": fact_type_label(canonical_type),
        "value": canonical_value,
        "source": str(source or "unknown"),
        "confidence": float(
            score_fact_confidence(
                source=source,
                evidence=evidence,
                method=method,
                template_prior=template_prior,
                extracted_count=extracted_count,
                fact_type=canonical_type,
            )
            if confidence is None
            else confidence
        ),
        "key": infer_fact_key_name(canonical_type),
    }
    if evidence is not None and str(evidence).strip():
        fact["evidence"] = str(evidence).strip()
    return fact


def to_confidence_score(raw_confidence):
    return resolve_template_prior(raw_confidence)


def get_extracted_results(result):
    extracted = result.get("extracted-results") or []

    if isinstance(extracted, str):
        return [extracted]

    values = []
    for item in extracted:
        if item is None:
            continue
        if isinstance(item, dict):
            for value in item.values():
                if value is not None:
                    values.append(str(value))
            continue
        values.append(str(item))
    return values


def get_best_match_location(result):
    for key in ("matched-at", "host", "url"):
        value = result.get(key)
        if value:
            return str(value)
    return None


def extract_path(location):
    if not location:
        return None

    parsed = urlparse(location)
    if parsed.path:
        return parsed.path
    return None


def output_matches_result(fact_type, result):
    labels = " ".join(
        value.lower()
        for value in (
            result.get("matcher-name"),
            result.get("extractor-name"),
            result.get("template-id"),
            (result.get("info") or {}).get("name"),
        )
        if value
    )

    lower_type = fact_type.lower()

    if "plugin" in lower_type:
        return True

    if "theme" in lower_type:
        return "plugin" not in labels or "theme" in labels

    if "version" in lower_type:
        return "panel" not in labels and "login" not in labels or "version" in labels

    if "panel" in lower_type or "login" in lower_type:
        return "version" not in labels or "panel" in labels or "login" in labels

    return True


def compact_values(values):
    output = []
    seen = set()

    for value in values:
        if value is None:
            continue
        text = str(value).strip()
        if not text or text in seen:
            continue
        seen.add(text)
        output.append(text)

    return output


def parse_json_lines(raw_results):
    results = []

    for line in raw_results.splitlines():
        payload = line.strip()
        if not payload:
            continue
        try:
            results.append(json.loads(payload))
        except json.JSONDecodeError:
            continue

    return results


def deduplicate_facts(facts):
    unique = []
    index_by_key = {}

    for fact in facts:
        key = (
            canonicalize_fact_type(fact.get("type")),
            canonicalize_fact_value(fact.get("type"), fact.get("value")),
            fact.get("source"),
        )

        existing_idx = index_by_key.get(key)
        if existing_idx is None:
            index_by_key[key] = len(unique)
            unique.append(fact)
            continue

        current = unique[existing_idx]
        current_conf = float(current.get("confidence", 0.0))
        incoming_conf = float(fact.get("confidence", 0.0))
        if incoming_conf > current_conf:
            current["confidence"] = incoming_conf

        incoming_evidence = str(fact.get("evidence") or "").strip()
        if incoming_evidence:
            current_evidence = str(current.get("evidence") or "").strip()
            if not current_evidence:
                current["evidence"] = incoming_evidence
            elif incoming_evidence not in current_evidence:
                current["evidence"] = f"{current_evidence} | {incoming_evidence}"

    return unique
