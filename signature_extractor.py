import argparse
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set

import yaml


PROTOCOL_KEYS = (
    "http",
    "headless",
    "dns",
    "network",
    "tcp",
    "ssl",
    "websocket",
    "whois",
    "code",
    "javascript",
    "file",
)

VARIABLE_INPUT_MAP = {
    "baseurl": "URL",
    "rooturl": "URL",
    "url": "URL",
    "hostname": "Domain",
    "host": "Domain",
    "fqdn": "Domain",
    "ip": "IP",
    "port": "Port",
}

TECHNOLOGY_RULES = {
    "WordPress": ("wordpress", "wp-content", "wp-json", "wp-login", "wp-admin"),
    "PHP": ("php", "phpsessid", ".php", "phpinfo"),
    "Django": ("django", "csrftoken", "django administration"),
    "Drupal": ("drupal",),
    "GitLab": ("gitlab", "sign_in"),
    "Grafana": ("grafana",),
    "Adminer": ("adminer",),
}

PARENT_TECH_RULES = {
    "WordPress": "Technology=PHP",
    "Drupal": "Technology=PHP",
    "Adminer": "Technology=PHP",
}

PRODUCT_TAG_STOPWORDS = {
    "tech",
    "detect",
    "detection",
    "discovery",
    "exposure",
    "misconfig",
    "cve",
    "vuln",
    "panel",
    "login",
    "default",
    "config",
    "file",
    "files",
    "generic",
}

PRODUCT_VENDOR_HINTS = {
    "wordpress": "wordpress",
    "drupal": "drupal",
    "django": "djangoproject",
    "grafana": "grafana",
    "gitlab": "gitlab",
    "php": "php",
    "adminer": "adminer",
    "magento": "adobe",
    "moodle": "moodle",
}


def parse_args():
    parser = argparse.ArgumentParser(
        description="Extract orchestration signatures from Nuclei templates."
    )
    parser.add_argument(
        "--templates-dir",
        required=True,
        help="Directory containing Nuclei YAML templates.",
    )
    parser.add_argument(
        "--output",
        default="generated_signatures.yaml",
        help="Output YAML file for extracted signatures.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print skipped files and scan statistics.",
    )
    return parser.parse_args()


def load_nuclei_template(path: Path) -> Dict[str, Any]:
    try:
        with path.open("r", encoding="utf-8") as file:
            data = yaml.safe_load(file) or {}
    except yaml.YAMLError as error:
        return {
            "ok": False,
            "reason": f"yaml_error: {error.__class__.__name__}",
            "data": None,
        }

    if not isinstance(data, dict):
        return {
            "ok": False,
            "reason": "not_mapping",
            "data": None,
        }

    if not data.get("id"):
        return {
            "ok": False,
            "reason": "missing_id",
            "data": None,
        }

    return {
        "ok": True,
        "reason": None,
        "data": data,
    }


def load_nuclei_templates(templates_dir: Path) -> Dict[str, Any]:
    template_paths = sorted(templates_dir.rglob("*.yaml")) + sorted(templates_dir.rglob("*.yml"))
    templates = []
    skipped = []

    for path in template_paths:
        loaded = load_nuclei_template(path)
        if not loaded["ok"]:
            skipped.append({
                "path": normalize_path(path),
                "reason": loaded["reason"],
            })
            continue
        templates.append({"path": path, "data": loaded["data"]})

    return {
        "templates": templates,
        "scanned_files": len(template_paths),
        "skipped": skipped,
    }


def extract_signature(template_path: Path, template_data: Dict[str, Any]) -> Dict[str, Any]:
    protocol = detect_protocol(template_data)
    tags = extract_tags(template_data)
    severity = str((template_data.get("info") or {}).get("severity") or "info").lower()
    paths = extract_paths(template_data, protocol)
    corpus = build_corpus(template_data, paths, tags)
    technologies = infer_technologies(corpus)
    semantic_inputs = infer_semantic_inputs(template_data, tags, technologies)
    preconditions = infer_preconditions(protocol, technologies, semantic_inputs)
    outputs = infer_outputs(template_data, tags, technologies, severity, corpus)
    variables = extract_template_variables(template_data)
    normalized_signature = build_signature(template_path, template_data)

    signature = {
        "id": str(template_data.get("id")).strip(),
        "template_path": normalize_path(template_path),
        "protocol": protocol,
        "tags": tags,
        "path": paths,
        "precondition": preconditions,
        "input": semantic_inputs,
        "output": outputs,
        "template_id": normalized_signature["template_id"],
        "product": normalized_signature["product"],
        "vendor": normalized_signature["vendor"],
        "version_hints": normalized_signature["version_hints"],
        "requires": normalized_signature["requires"],
        "identity": normalized_signature["identity"],
        "matching_info": normalized_signature["matching_info"],
        "requirements": normalized_signature["requirements"],
        "run_info": normalized_signature["run_info"],
        "meta_outputs": normalized_signature["meta_outputs"],
    }

    if variables:
        signature["variables"] = variables

    description = str((template_data.get("info") or {}).get("description") or "").strip()
    if description:
        signature["description"] = description

    confidence = infer_confidence(severity, tags)
    if confidence:
        signature["confidence"] = confidence

    cost = infer_cost(template_data, paths)
    if cost:
        signature["cost"] = cost

    return signature


def build_signature(template_path: Path, template_data: Dict[str, Any]) -> Dict[str, Any]:
    protocol = detect_protocol(template_data)
    tags = extract_tags(template_data)
    severity = str((template_data.get("info") or {}).get("severity") or "info").lower()
    paths = extract_paths(template_data, protocol)
    corpus = build_corpus(template_data, paths, tags)
    technologies = infer_technologies(corpus)

    template_id = str(template_data.get("id") or "").strip()
    template_name = str((template_data.get("info") or {}).get("name") or template_id).strip()
    product = infer_product(template_data, tags, technologies, template_id)
    vendor = infer_vendor(template_data, product)
    version_hints = infer_version_hints(template_data)
    version_constraints = infer_version_constraints(template_data)
    requires = infer_requires(template_data, protocol, technologies, tags)
    required_vars = extract_raw_template_variables(template_data)
    input_binding = extract_variable_fact_bindings(template_data)
    outputs = infer_outputs(template_data, tags, technologies, severity, corpus)
    produced_fact_types = extract_produced_fact_types(outputs)
    cost = infer_cost(template_data, paths)
    confidence = infer_confidence(severity, tags)
    specificity = infer_specificity(requires, tags, paths)
    intrusiveness = infer_intrusiveness(template_data, protocol, tags, paths)
    category = infer_category(template_data, tags, severity, protocol)
    aliases = infer_aliases(template_data, product, technologies, tags)
    services = infer_services(template_data, protocol, tags)
    source_path = normalize_path(template_path)

    identity = {
        "template_id": template_id,
        "name": template_name,
        "protocol": protocol,
        "category": category,
        "source_path": source_path,
    }

    matching_info = {
        "product": product,
        "vendor": vendor,
        "tags": tags,
        "version_constraints": version_constraints,
        "service": services,
        "paths": paths,
        "aliases": aliases,
    }

    requirements = {
        "required_facts": requires,
        "required_vars": required_vars,
    }

    run_info = {
        "engine": "nuclei",
        "template_path": source_path,
        "command_template": (
            "nuclei -t {template_path} -u {target} "
            "-jsonl -silent -no-color {extra_args}"
        ),
        "input_binding": input_binding,
    }

    meta_outputs = {
        "severity": severity,
        "produced_fact_types": produced_fact_types,
        "cost": cost,
        "specificity": specificity,
        "confidence": confidence,
        "intrusiveness": intrusiveness,
    }

    return {
        "template_id": template_id,
        "product": product,
        "vendor": vendor,
        "tags": tags,
        "version_hints": version_hints,
        "protocol": protocol,
        "requires": requires,
        "identity": identity,
        "matching_info": matching_info,
        "requirements": requirements,
        "run_info": run_info,
        "meta_outputs": meta_outputs,
    }


def detect_protocol(template_data: Dict[str, Any]) -> str:
    for key in PROTOCOL_KEYS:
        if key in template_data:
            return key
    return "unknown"


def extract_tags(template_data: Dict[str, Any]) -> List[str]:
    tags = (template_data.get("info") or {}).get("tags") or []
    if isinstance(tags, str):
        tags = [tag.strip() for tag in tags.split(",")]

    unique = []
    seen = set()
    for tag in tags:
        value = str(tag).strip()
        if not value:
            continue
        lowered = value.lower()
        if lowered in seen:
            continue
        seen.add(lowered)
        unique.append(lowered)
    return unique


def extract_paths(template_data: Dict[str, Any], protocol: str) -> List[str]:
    request_blocks = template_data.get(protocol) or []
    if isinstance(request_blocks, dict):
        request_blocks = [request_blocks]

    paths = []
    seen = set()

    for block in request_blocks:
        if not isinstance(block, dict):
            continue

        for path_value in ensure_list(block.get("path")):
            normalized = str(path_value).strip()
            if normalized and normalized not in seen:
                seen.add(normalized)
                paths.append(normalized)

        for raw_request in ensure_list(block.get("raw")):
            parsed_path = parse_raw_request_path(str(raw_request))
            if parsed_path and parsed_path not in seen:
                seen.add(parsed_path)
                paths.append(parsed_path)

    return paths


def build_corpus(
    template_data: Dict[str, Any],
    paths: List[str],
    tags: List[str],
) -> str:
    parts = [
        str(template_data.get("id") or ""),
        str((template_data.get("info") or {}).get("name") or ""),
        str((template_data.get("info") or {}).get("description") or ""),
        " ".join(tags),
        " ".join(paths),
        " ".join(flatten_strings(template_data)),
    ]
    return " ".join(parts).lower()


def infer_technologies(corpus: str) -> List[str]:
    matches = []
    for technology, keywords in TECHNOLOGY_RULES.items():
        if any(keyword in corpus for keyword in keywords):
            matches.append(technology)

    if any(tech in matches for tech in ("WordPress", "Drupal", "Adminer")) and "PHP" in matches:
        matches = [tech for tech in matches if tech != "PHP"]

    return matches


def infer_semantic_inputs(
    template_data: Dict[str, Any],
    tags: List[str],
    technologies: List[str],
) -> List[str]:
    template_id = str(template_data.get("id") or "").lower()
    corpus = build_corpus(template_data, [], tags)
    inputs = []

    if is_wordpress_hidden_login_template(template_id, tags, corpus):
        inputs.append("wordpress-plugin")
    elif is_wordpress_plugin_template(tags, corpus):
        inputs.append("Technology=WordPress")
    elif technologies:
        primary = technologies[0]
        if is_technology_detection_template(template_id, tags):
            if primary in PARENT_TECH_RULES and primary != "PHP":
                inputs.append(PARENT_TECH_RULES[primary])
            else:
                inputs.append("URL")
        elif primary == "PHP":
            inputs.append("Technology=PHP")
        else:
            inputs.append(f"Technology={primary}")
    else:
        variables = extract_template_variables(template_data)
        if "URL" in variables:
            inputs.append("URL")

    if not inputs:
        inputs.append("URL")

    return deduplicate(inputs)


def infer_preconditions(
    protocol: str,
    technologies: List[str],
    semantic_inputs: List[str],
) -> List[str]:
    preconditions = []

    if protocol in {"http", "headless", "websocket"}:
        preconditions.append("http reachable")

    for value in semantic_inputs:
        if value == "URL":
            continue
        if value not in preconditions:
            preconditions.append(value)

    return deduplicate(preconditions)


def infer_outputs(
    template_data: Dict[str, Any],
    tags: List[str],
    technologies: List[str],
    severity: str,
    corpus: str,
) -> List[str]:
    template_id = str(template_data.get("id") or "").lower()
    outputs = []
    technology_detection = is_technology_detection_template(template_id, tags)
    plugin_template = is_wordpress_plugin_template(tags, corpus)

    if "phpinfo" in corpus:
        outputs.extend(["phpinfo-page", "php-version"])

    if "config.json" in corpus:
        outputs.append("config-json-file")

    if plugin_template:
        outputs.extend(["wordpress-plugin", "wordpress-theme"])

    if is_wordpress_hidden_login_template(template_id, tags, corpus):
        outputs.append("wordpress-hidden-login")

    if is_panel_template(tags, corpus) and not technology_detection:
        outputs.extend(infer_panel_outputs(technologies))

    if has_version_extractor(template_data, corpus) and not plugin_template and not technology_detection:
        outputs.extend(infer_version_outputs(technologies))

    if technology_detection:
        for technology in technologies:
            outputs.append(f"Technology={technology}")

    if severity not in {"", "info", "unknown"} and not outputs:
        outputs.append(f"Vulnerability={template_data.get('id')}")

    return deduplicate(outputs)


def infer_panel_outputs(technologies: List[str]) -> List[str]:
    outputs = []

    for technology in technologies:
        slug = technology.lower()
        if technology == "Adminer":
            outputs.extend(["adminer-panel", "adminer-version"])
            continue
        if technology == "Django":
            outputs.extend(["django-admin-panel", "django-version"])
            continue
        if technology == "Drupal":
            outputs.append("drupal-login-panel")
            continue
        if technology == "GitLab":
            outputs.append("gitlab-login-panel")
            continue
        if technology == "Grafana":
            outputs.extend(["grafana-login-panel", "grafana-version"])
            continue
        outputs.append(f"{slug}-login-panel")

    return outputs


def infer_version_outputs(technologies: List[str]) -> List[str]:
    outputs = []
    for technology in technologies:
        slug = technology.lower()
        if technology == "PHP":
            outputs.append("php-version")
        elif technology == "Grafana":
            outputs.append("grafana-version")
        elif technology == "Django":
            outputs.append("django-version")
        elif technology == "Adminer":
            outputs.append("adminer-version")
        else:
            outputs.append(f"{slug}-version")
    return outputs


def extract_template_variables(template_data: Dict[str, Any]) -> List[str]:
    variables = []
    pattern = re.compile(r"\{\{\s*([A-Za-z0-9_]+)\s*\}\}")

    for value in flatten_strings(template_data):
        for match in pattern.findall(value):
            mapped = VARIABLE_INPUT_MAP.get(match.lower())
            if mapped:
                variables.append(mapped)

    return deduplicate(variables)


def has_version_extractor(template_data: Dict[str, Any], corpus: str) -> bool:
    if "version" in corpus:
        return True

    for item in flatten_objects(template_data):
        if isinstance(item, dict):
            name = str(item.get("name") or "").lower()
            if "version" in name:
                return True

    return False


def is_technology_detection_template(template_id: str, tags: List[str]) -> bool:
    if any(tag in {"plugin", "theme", "panel", "login", "config", "exposure", "vuln"} for tag in tags):
        return False
    if "fingerprint" in tags:
        return True
    return any(keyword in template_id for keyword in ("detect", "fingerprint", "tech"))


def is_panel_template(tags: List[str], corpus: str) -> bool:
    if any(tag in {"panel", "login", "admin"} for tag in tags):
        return True
    return any(keyword in corpus for keyword in ("login", "panel", "sign_in", "/admin"))


def is_wordpress_plugin_template(tags: List[str], corpus: str) -> bool:
    return (
        "wordpress" in corpus
        and ("plugin" in tags or "theme" in tags or "wp-content/plugins/" in corpus)
    )


def is_wordpress_hidden_login_template(template_id: str, tags: List[str], corpus: str) -> bool:
    return "wordpress" in corpus and (
        "hidden-login" in template_id
        or "wp-plugin" in tags
        or "aiowpsec" in corpus
    )


def infer_confidence(severity: str, tags: List[str]) -> str:
    if severity in {"critical", "high", "medium", "low"}:
        return "high" if severity in {"critical", "high"} else "medium"
    if "panel" in tags or "login" in tags:
        return "high"
    return "medium"


def infer_cost(template_data: Dict[str, Any], paths: List[str]) -> str:
    threads = template_data.get("threads")
    if isinstance(threads, int) and threads >= 25:
        return "high"
    if len(paths) >= 5:
        return "medium"
    return "low"


def infer_product(
    template_data: Dict[str, Any],
    tags: List[str],
    technologies: List[str],
    template_id: str,
) -> str:
    info = template_data.get("info") or {}
    metadata = info.get("metadata") or {}

    if isinstance(metadata, dict):
        for key in (
            "product",
            "software",
            "technology",
            "cms",
            "framework",
            "vendor_product",
        ):
            value = metadata.get(key)
            if value is None:
                continue
            if isinstance(value, list):
                value = value[0] if value else None
            text = normalize_product_token(value)
            if text:
                return text

    if technologies:
        return normalize_product_token(technologies[0]) or "unknown"

    for tag in tags:
        lowered = normalize_product_token(tag)
        if lowered and lowered not in PRODUCT_TAG_STOPWORDS:
            return lowered

    prefix = normalize_product_token(str(template_id).split("-", 1)[0])
    if prefix and prefix not in PRODUCT_TAG_STOPWORDS:
        return prefix

    return "unknown"


def infer_vendor(template_data: Dict[str, Any], product: str) -> str:
    info = template_data.get("info") or {}
    metadata = info.get("metadata") or {}

    if isinstance(metadata, dict):
        for key in (
            "vendor",
            "manufacturer",
            "author",
            "product_vendor",
            "company",
        ):
            value = metadata.get(key)
            if value is None:
                continue
            if isinstance(value, list):
                value = value[0] if value else None
            text = normalize_product_token(value)
            if text:
                return text

    return PRODUCT_VENDOR_HINTS.get(product, "unknown")


def infer_version_hints(template_data: Dict[str, Any]) -> List[str]:
    version_pattern = re.compile(r"\b\d+(?:\.\d+)+\b")
    hints = []

    for text in flatten_strings(template_data):
        hints.extend(version_pattern.findall(text))

    return deduplicate(hints)


def infer_requires(
    template_data: Dict[str, Any],
    protocol: str,
    technologies: List[str],
    tags: List[str],
) -> List[str]:
    semantic_inputs = infer_semantic_inputs(template_data, tags, technologies)
    preconditions = infer_preconditions(protocol, technologies, semantic_inputs)
    return deduplicate([*semantic_inputs, *preconditions])


def infer_category(
    template_data: Dict[str, Any],
    tags: List[str],
    severity: str,
    protocol: str,
) -> str:
    template_id = str(template_data.get("id") or "").strip().lower()
    tag_set = set(tags)

    if template_id.startswith("cve-") or "cve" in tag_set:
        return "generic-cve"
    if "misconfig" in tag_set:
        return "misconfig"
    if "exposure" in tag_set or "config" in tag_set:
        return "exposure"
    if any(tag in tag_set for tag in {"tech", "detect", "detection", "discovery"}):
        return "detection"
    if severity in {"high", "critical"}:
        return "vulnerability"
    return protocol or "generic"


def infer_services(
    template_data: Dict[str, Any],
    protocol: str,
    tags: List[str],
) -> List[str]:
    services = []

    if protocol in {"http", "headless", "websocket"}:
        services.append("http")
    elif protocol and protocol != "unknown":
        services.append(protocol)

    service_tag_candidates = {
        "dns",
        "ssh",
        "ftp",
        "smtp",
        "mysql",
        "postgres",
        "postgresql",
        "redis",
        "mongodb",
        "rdp",
        "ldap",
        "snmp",
        "telnet",
        "http",
        "https",
    }
    for tag in tags:
        lowered = str(tag).strip().lower()
        if lowered in service_tag_candidates:
            services.append("http" if lowered == "https" else lowered)

    if "service" in template_data and template_data.get("service"):
        for item in ensure_list(template_data.get("service")):
            services.append(str(item).strip().lower())

    return deduplicate(services)


def infer_aliases(
    template_data: Dict[str, Any],
    product: str,
    technologies: List[str],
    tags: List[str],
) -> List[str]:
    aliases = []
    info = template_data.get("info") or {}
    metadata = info.get("metadata") or {}

    aliases.extend([product, *technologies])
    aliases.extend(tags)

    if isinstance(metadata, dict):
        for key in (
            "aliases",
            "alias",
            "cpe",
            "product",
            "vendor_product",
            "fofa-query",
            "shodan-query",
            "google-query",
            "query",
        ):
            value = metadata.get(key)
            if value is None:
                continue
            for item in ensure_list(value):
                aliases.append(str(item).strip().lower())

    normalized = []
    for alias in aliases:
        token = normalize_product_token(alias)
        if token:
            normalized.append(token)

    return deduplicate(normalized)


def infer_version_constraints(template_data: Dict[str, Any]) -> List[str]:
    constraints = []

    comparator_pattern = re.compile(r"(?:<=|>=|<|>|=)\s*v?\d+(?:\.\d+)+")
    phrase_pattern = re.compile(
        r"(?:before|prior\s+to|through|upto|up\s+to|below)\s+v?\d+(?:\.\d+)+",
        flags=re.IGNORECASE,
    )

    for text in flatten_strings(template_data):
        constraints.extend(comparator_pattern.findall(text))
        constraints.extend(phrase_pattern.findall(text))

    return deduplicate([str(item).strip().lower() for item in constraints])


def infer_specificity(required_facts: List[str], tags: List[str], paths: List[str]) -> float:
    required_score = min(len(required_facts), 5) * 0.16
    tag_score = min(len(tags), 6) * 0.06
    path_score = min(len(paths), 5) * 0.07
    return round(min(required_score + tag_score + path_score, 1.0), 4)


def infer_intrusiveness(
    template_data: Dict[str, Any],
    protocol: str,
    tags: List[str],
    paths: List[str],
) -> str:
    tag_set = {str(tag).strip().lower() for tag in tags}

    threads = template_data.get("threads")
    if isinstance(threads, int) and threads >= 40:
        return "high"

    if any(tag in tag_set for tag in {"fuzz", "fuzzing", "bruteforce", "rce", "sqli"}):
        return "high"

    if protocol == "network" or len(paths) >= 12:
        return "medium"

    if any(tag in tag_set for tag in {"tech", "detect", "discovery", "passive"}):
        return "low"

    return "medium"


def extract_produced_fact_types(outputs: List[str]) -> List[str]:
    produced = []
    for item in outputs:
        text = str(item).strip()
        if not text:
            continue
        if "=" in text:
            text = text.split("=", 1)[0].strip()
        produced.append(text)
    return deduplicate(produced)


def extract_raw_template_variables(template_data: Dict[str, Any]) -> List[str]:
    variables = []
    pattern = re.compile(r"\{\{\s*([A-Za-z0-9_]+)\s*\}\}")

    for value in flatten_strings(template_data):
        for match in pattern.findall(value):
            variables.append(match)

    return deduplicate(variables)


def extract_variable_fact_bindings(template_data: Dict[str, Any]) -> Dict[str, str]:
    bindings = {}
    for raw_variable in extract_raw_template_variables(template_data):
        mapped = VARIABLE_INPUT_MAP.get(str(raw_variable).strip().lower())
        if mapped:
            bindings[raw_variable] = mapped
    return bindings


def normalize_product_token(value: Any) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip().lower()
    if not text:
        return None
    return re.sub(r"\s+", "-", text)


def normalize_path(path: Path) -> str:
    return path.as_posix()


def parse_raw_request_path(raw_request: str) -> Optional[str]:
    for line in raw_request.splitlines():
        line = line.strip()
        if not line:
            continue
        match = re.match(r"^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+(\S+)", line)
        if match:
            return match.group(2)
        break
    return None


def flatten_strings(value: Any) -> List[str]:
    results = []

    if isinstance(value, dict):
        for item in value.values():
            results.extend(flatten_strings(item))
    elif isinstance(value, list):
        for item in value:
            results.extend(flatten_strings(item))
    elif isinstance(value, str):
        results.append(value)

    return results


def flatten_objects(value: Any) -> Iterable[Any]:
    if isinstance(value, dict):
        yield value
        for item in value.values():
            yield from flatten_objects(item)
    elif isinstance(value, list):
        for item in value:
            yield from flatten_objects(item)
    else:
        yield value


def ensure_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def deduplicate(values: Iterable[str]) -> List[str]:
    unique = []
    seen: Set[str] = set()

    for value in values:
        text = str(value).strip()
        if not text or text in seen:
            continue
        seen.add(text)
        unique.append(text)

    return unique


def write_signature_database(output_path: Path, signatures: List[Dict[str, Any]]) -> None:
    payload = {
        "templates": signatures,
    }

    with output_path.open("w", encoding="utf-8") as file:
        yaml.safe_dump(payload, file, sort_keys=False, allow_unicode=True)


def main():
    args = parse_args()
    templates_dir = Path(args.templates_dir)
    output_path = Path(args.output)

    if not templates_dir.exists():
        raise SystemExit(f"Templates directory does not exist: {templates_dir}")

    if not templates_dir.is_dir():
        raise SystemExit(f"Templates path is not a directory: {templates_dir}")

    loaded_templates = load_nuclei_templates(templates_dir)
    signatures = [
        extract_signature(item["path"], item["data"])
        for item in loaded_templates["templates"]
    ]

    write_signature_database(output_path, signatures)
    print(f"Extracted {len(signatures)} signatures to {output_path}")
    print(
        f"Scanned {loaded_templates['scanned_files']} YAML files, "
        f"skipped {len(loaded_templates['skipped'])}."
    )

    if args.verbose and loaded_templates["skipped"]:
        print("Skipped files:")
        for item in loaded_templates["skipped"][:20]:
            print(f"- {item['path']} [{item['reason']}]")


if __name__ == "__main__":
    main()
