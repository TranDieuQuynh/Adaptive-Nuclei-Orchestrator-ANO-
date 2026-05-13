<<<<<<< HEAD
from __future__ import annotations

from typing import Dict, List

from models import Fact


class Blackboard:
    def __init__(self):
        self.facts_by_type: Dict[str, List[Fact]] = {}
        self.facts_by_id: Dict[str, Fact] = {}
        # (type, normalized_value, target) -> fact.id
        self.fact_keys = {}
        # provenance: fact.id -> List[template_id]
        self.provenance: Dict[str, List[str]] = {}

    def add_if_new_or_better(self, fact, provenance=None):
        key = fact.key()

        if key in self.fact_keys:
            old_id = self.fact_keys[key]
            old_fact = self.facts_by_id[old_id]

            if fact.confidence <= old_fact.confidence:
                # Vẫn lưu provenance nếu có
                if provenance:
                    self._add_provenance(old_id, provenance)
                return False

            self._remove(old_fact)

        self.facts_by_id[fact.id] = fact
        self.facts_by_type.setdefault(fact.type, []).append(fact)
        self.fact_keys[key] = fact.id
        if provenance:
            self._add_provenance(fact.id, provenance)
        return True

    def add_fact(self, fact, provenance=None):
        """Alias cho add_if_new_or_better, cho phép truyền provenance."""
        return self.add_if_new_or_better(fact, provenance)

    def _add_provenance(self, fact_id, provenance):
        if not provenance:
            return
        if fact_id not in self.provenance:
            self.provenance[fact_id] = []
        if isinstance(provenance, list):
            for p in provenance:
                if p not in self.provenance[fact_id]:
                    self.provenance[fact_id].append(p)
        else:
            if provenance not in self.provenance[fact_id]:
                self.provenance[fact_id].append(provenance)

    def _remove(self, fact):
        self.facts_by_id.pop(fact.id, None)
        self.fact_keys.pop(fact.key(), None)
        if fact.type in self.facts_by_type:
            self.facts_by_type[fact.type] = [
                f for f in self.facts_by_type[fact.type]
                if f.id != fact.id
            ]
        # Không xóa provenance để trace được lịch sử

    def get_by_type(self, t):
        return self.facts_by_type.get(t, [])

    def get_by_id(self, fact_id):
        return self.facts_by_id.get(fact_id)

    def get_latest(self, k, t=None):
        """Trả về k fact mới nhất theo type t (nếu có), hoặc toàn bộ."""
        if t is not None:
            facts = self.facts_by_type.get(t, [])
        else:
            facts = list(self.facts_by_id.values())
        # sort theo timestamp giảm dần
        return sorted(facts, key=lambda f: getattr(f, "timestamp", 0), reverse=True)[:k]

    def update_confidence(self, fact_id, new_confidence):
        fact = self.facts_by_id.get(fact_id)
        if not fact:
            return False
        # Tạo fact mới với confidence mới (Fact là frozen)
        new_fact = Fact(
            id=fact.id,
            type=fact.type,
            value=fact.value,
            confidence=new_confidence,
            source=fact.source,
            target=fact.target,
            discovery_depth=fact.discovery_depth,
            timestamp=fact.timestamp,
            ttl=fact.ttl,
            tags=fact.tags,
            metadata=fact.metadata,
            provenance=fact.provenance,
        )
        self.facts_by_id[fact_id] = new_fact
        # update trong facts_by_type
        if fact.type in self.facts_by_type:
            for idx, f in enumerate(self.facts_by_type[fact.type]):
                if f.id == fact_id:
                    self.facts_by_type[fact.type][idx] = new_fact
        return True

    def deduplicate(self):
        """Giữ lại fact có confidence cao nhất cho mỗi key, không xóa provenance cũ."""
        keep_ids = set()
        for key, fact_id in self.fact_keys.items():
            keep_ids.add(fact_id)
        # Xóa các fact không nằm trong keep_ids
        remove_ids = [fid for fid in self.facts_by_id if fid not in keep_ids]
        for fid in remove_ids:
            fact = self.facts_by_id[fid]
            self._remove(fact)

    def has_type(self, t):
        return bool(self.facts_by_type.get(t))

    def has_all_types(self, types):
        return all(self.has_type(t) for t in types)

    def all_facts(self):
        return list(self.facts_by_id.values())
=======
﻿from copy import deepcopy
from datetime import datetime, timezone
import json
import re
from urllib.parse import urlparse

from confidence_model import combine_confidence, resolve_source_reliability


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
    "software-version": "software_version",
    "software version": "software_version",
    "software_version": "software_version",
    "version": "software_version",
    "vendor": "vendor",
    "framework": "framework",
    "cms": "cms",
    "plugin": "plugin",
    "wordpress-plugin": "plugin",
    "wordpress-theme": "plugin",
    "phpinfo-page": "path",
    "config-json-file": "path",
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

DEFAULT_MIN_CONFIDENCE_KEEP = 0.45
DEFAULT_CONFIDENCE_CAP = 0.97

CONFLICT_SENSITIVE_FACT_TYPES = {
    "software_product",
    "software_version",
    "vendor",
    "framework",
    "cms",
    "plugin",
    "protocol",
    "service",
}

CONFLICT_PENALTY_MIN_FACTOR = 0.72

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


def fact_type_label(fact_type):
    canonical_type = FACT_TYPE_ALIASES.get(
        str(fact_type or "").strip().lower().replace("_", "-").replace(" ", "-"),
        str(fact_type or "").strip().lower().replace("-", "_"),
    )
    if canonical_type == "software_product":
        return "product"
    if canonical_type == "software_version":
        return "version"
    return canonical_type


def fact_key_name(fact_type):
    canonical_type = FACT_TYPE_ALIASES.get(
        str(fact_type or "").strip().lower().replace("_", "-").replace(" ", "-"),
        str(fact_type or "").strip().lower().replace("-", "_"),
    )
    if canonical_type in {"software_product", "vendor", "framework", "cms", "plugin", "service", "protocol", "header"}:
        return "name"
    if canonical_type in {"software_version", "port"}:
        return "number"
    if canonical_type == "title":
        return "text"
    if canonical_type == "path":
        return "path"
    if canonical_type == "url":
        return "url"
    if canonical_type == "domain":
        return "host"
    if canonical_type == "ip":
        return "address"
    if canonical_type == "vulnerability":
        return "id"
    return "value"


class Blackboard:
    def __init__(
        self,
        initial_facts=None,
        min_confidence_keep=DEFAULT_MIN_CONFIDENCE_KEEP,
        confidence_cap=DEFAULT_CONFIDENCE_CAP,
    ):
        self._records = []
        self._records_by_type = {}
        self._fact_index = {}
        self._history = []
        self._next_sequence = 1
        self._min_confidence_keep = self._clamp_confidence(min_confidence_keep)
        self._confidence_cap = self._clamp_confidence(confidence_cap)

        if initial_facts:
            self.add_facts(initial_facts, reason="seed")
        self.prune_low_confidence(self._min_confidence_keep)
        self.snapshot("initial")

    def add_fact(self, fact, reason=None, metadata=None):
        normalized = self._normalize_fact(fact)
        key = self._fact_key(normalized)
        if key in self._fact_index:
            self._merge_existing_fact(self._fact_index[key], normalized)
            return None

        conflicts = self._find_conflicting_records(normalized)
        if conflicts:
            self._apply_conflict_resolution(normalized, conflicts)

        observed_at = normalized.get("timestamp") or self._utcnow()
        normalized["timestamp"] = observed_at

        record = {
            "fact": normalized,
            "sequence": self._next_sequence,
            "timestamp": observed_at,
            "reason": reason,
            "metadata": deepcopy(metadata) if metadata else {},
        }
        self._records.append(record)
        self._fact_index[key] = record
        self._records_by_type.setdefault(normalized.get("type"), []).append(record)
        self._next_sequence += 1
        return deepcopy(normalized)

    def add_facts(self, facts, reason=None, metadata=None):
        added = []
        for fact in facts or []:
            created = self.add_fact(fact, reason=reason, metadata=metadata)
            if created is not None:
                added.append(created)
        return added

    def fact_exists(self, fact_type, value=None):
        if value is None and isinstance(fact_type, str) and "=" in fact_type:
            fact_type, value = fact_type.split("=", 1)

        expected_type = self._canonical_fact_type(fact_type)
        expected_value = None
        if value is not None:
            expected_value = self._canonical_fact_value(expected_type, value)

        for record in self._records:
            fact = record["fact"]
            current_type = self._canonical_fact_type(fact.get("type"))
            if current_type != expected_type:
                continue
            if expected_value is None:
                return True
            current_value = self._canonical_fact_value(current_type, fact.get("value"))
            if current_value == expected_value:
                return True
        return False

    def query_by_type(self, fact_type):
        expected_type = self._canonical_fact_type(fact_type)
        records = self._records_by_type.get(expected_type, [])
        return [deepcopy(record["fact"]) for record in records]

    def update_fact_confidence(self, fact_type, value, new_confidence, evidence=None):
        normalized_type = self._canonical_fact_type(fact_type)
        normalized_value = self._canonical_fact_value(normalized_type, value)
        key = (normalized_type, normalized_value)
        record = self._fact_index.get(key)
        if record is None:
            return None

        fact = record["fact"]
        fact["confidence"] = max(0.0, min(float(new_confidence), 1.0))

        incoming_evidence = str(evidence or "").strip()
        if incoming_evidence:
            current_evidence = str(fact.get("evidence") or "").strip()
            if not current_evidence:
                fact["evidence"] = incoming_evidence
            elif incoming_evidence not in current_evidence:
                fact["evidence"] = f"{current_evidence} | {incoming_evidence}"

        return deepcopy(fact)

    def get_latest_facts(self, k=5, fact_types=None):
        count = self._normalize_count(k)
        if count == 0:
            return []
        records = self._records
        if fact_types is not None:
            records = self._records_for_types(fact_types)
        return [
            deepcopy(record["fact"])
            for record in records[-count:]
        ]

    def get_latest_facts_by_type(self, k=3, fact_types=None):
        count = self._normalize_count(k)
        latest = {}

        for fact_type in self._normalize_fact_types(fact_types):
            records = self._records_by_type.get(fact_type, [])
            if count == 0 or not records:
                continue
            latest[fact_type] = [
                deepcopy(record["fact"])
                for record in records[-count:]
            ]

        return latest

    def select_facts(
        self,
        strategy="hybrid",
        k_latest=20,
        k_latest_per_type=3,
        fact_types=None,
    ):
        mode = str(strategy or "hybrid").strip().lower()

        if mode == "all":
            return self.get_all_facts()

        selected = []
        if mode in ("global", "hybrid"):
            selected.extend(self.get_latest_facts(k=k_latest))

        if mode in ("per-type", "per_type", "hybrid"):
            latest_by_type = self.get_latest_facts_by_type(
                k=k_latest_per_type,
                fact_types=fact_types,
            )
            for facts in latest_by_type.values():
                selected.extend(facts)

        if not selected:
            return []

        deduplicated = []
        seen = set()
        for fact in selected:
            key = self._fact_key(fact)
            if key in seen:
                continue
            seen.add(key)
            deduplicated.append(fact)

        deduplicated.sort(key=self._fact_sequence)
        return deduplicated

    def snapshot(self, label=None, metadata=None):
        snapshot = {
            "label": label or f"snapshot-{len(self._history) + 1}",
            "timestamp": self._utcnow(),
            "metadata": deepcopy(metadata) if metadata else {},
            "fact_count": len(self._records),
            "facts": self.get_all_facts(),
        }
        self._history.append(snapshot)
        return deepcopy(snapshot)

    def get_all_facts(self):
        return [deepcopy(record["fact"]) for record in self._records]

    def prune_low_confidence(self, threshold=None, protected_types=None):
        min_confidence = (
            self._min_confidence_keep
            if threshold is None
            else self._clamp_confidence(threshold)
        )
        protected = {
            self._canonical_fact_type(item)
            for item in (protected_types or [])
            if str(item or "").strip()
        }

        kept_records = []
        removed_facts = []

        for record in self._records:
            fact = record["fact"]
            fact_type = self._canonical_fact_type(fact.get("type"))
            confidence = self._clamp_confidence(fact.get("confidence", 0.0))

            if fact_type in protected or confidence >= min_confidence:
                kept_records.append(record)
            else:
                removed_facts.append(deepcopy(fact))

        if not removed_facts:
            return []

        self._records = kept_records
        self._fact_index = {}
        self._records_by_type = {}

        for record in self._records:
            fact = record["fact"]
            key = self._fact_key(fact)
            self._fact_index[key] = record
            self._records_by_type.setdefault(fact.get("type"), []).append(record)

        return removed_facts

    def export_history(self):
        return deepcopy(self._history)

    def save_facts(self, path):
        with open(path, "w", encoding="utf-8") as file:
            json.dump(self.get_all_facts(), file, indent=2, ensure_ascii=False)

    def save_history(self, path):
        with open(path, "w", encoding="utf-8") as file:
            json.dump(self.export_history(), file, indent=2, ensure_ascii=False)

    def _normalize_fact(self, fact):
        if not isinstance(fact, dict):
            raise TypeError(f"Fact must be dict, got {type(fact)!r}")

        raw_type = str(fact.get("type") or "").strip()
        fact_type = self._canonical_fact_type(raw_type)
        raw_value = str(fact.get("value") or "").strip()
        fact_value = self._canonical_fact_value(fact_type, raw_value)

        normalized = {
            "type": fact_type,
            "type_label": str(fact.get("type_label") or fact_type_label(fact_type)).strip() or fact_type_label(fact_type),
            "value": fact_value,
            "source": str(fact.get("source") or "unknown").strip(),
            "confidence": self._clamp_confidence(fact.get("confidence", 0.5)),
            "key": str(fact.get("key") or fact_key_name(fact_type)).strip() or fact_key_name(fact_type),
            "support_sources": [str(fact.get("source") or "unknown").strip()],
        }
        source_detail = fact.get("source_detail")
        if source_detail is not None and str(source_detail).strip():
            normalized["source_detail"] = str(source_detail).strip()
        evidence = fact.get("evidence")
        if evidence is not None and str(evidence).strip():
            normalized["evidence"] = str(evidence).strip()
        evidence_ref = fact.get("evidence_ref")
        if evidence_ref is not None and str(evidence_ref).strip():
            normalized["evidence_ref"] = str(evidence_ref).strip()
        declared_confidence = fact.get("declared_confidence")
        if declared_confidence is not None and str(declared_confidence).strip():
            normalized["declared_confidence"] = str(declared_confidence).strip().lower()
        template_fact_confidence = fact.get("template_fact_confidence")
        if template_fact_confidence is not None:
            normalized["template_fact_confidence"] = self._clamp_confidence(template_fact_confidence)
        evidence_detail = fact.get("evidence_detail")
        if isinstance(evidence_detail, dict) and evidence_detail:
            normalized["evidence_detail"] = deepcopy(evidence_detail)
        timestamp = fact.get("timestamp")
        if timestamp is not None and str(timestamp).strip():
            normalized["timestamp"] = str(timestamp).strip()
        if not normalized["type"]:
            raise ValueError(f"Fact missing type: {fact!r}")
        return normalized

    def _fact_key(self, fact):
        return fact.get("type"), str(fact.get("value"))

    def _fact_sequence(self, fact):
        record = self._fact_index.get(self._fact_key(fact))
        if record is None:
            return 0
        return record["sequence"]

    def _normalize_count(self, value):
        try:
            count = int(value)
        except (TypeError, ValueError):
            return 0
        return max(count, 0)

    def _normalize_fact_types(self, fact_types=None):
        if fact_types is None:
            return sorted(self._records_by_type.keys())

        normalized = []
        seen = set()
        for fact_type in fact_types:
            text = str(fact_type or "").strip()
            if not text or text in seen:
                continue
            seen.add(text)
            normalized.append(text)
        return normalized

    def _records_for_types(self, fact_types):
        selected = []
        seen = set()

        for fact_type in self._normalize_fact_types(fact_types):
            for record in self._records_by_type.get(fact_type, []):
                sequence = record["sequence"]
                if sequence in seen:
                    continue
                seen.add(sequence)
                selected.append(record)

        selected.sort(key=lambda item: item["sequence"])
        return selected

    def _utcnow(self):
        return datetime.now(timezone.utc).isoformat()

    def _merge_existing_fact(self, record, incoming_fact):
        current = record["fact"]
        current_source = str(current.get("source") or "unknown").strip()
        incoming_source = str(incoming_fact.get("source") or "unknown").strip()
        same_source = current_source == incoming_source
        merged_confidence = combine_confidence(
            existing_confidence=float(current.get("confidence", 0.0)),
            new_confidence=float(incoming_fact.get("confidence", 0.0)),
            same_source=same_source,
        )
        current["confidence"] = self._clamp_confidence(merged_confidence)

        support_sources = current.get("support_sources")
        if not isinstance(support_sources, list):
            support_sources = [current_source] if current_source else []
        if incoming_source and incoming_source not in support_sources:
            support_sources.append(incoming_source)
        current["support_sources"] = support_sources

        # Prefer strongest source as canonical source label for fused fact.
        if incoming_source:
            if resolve_source_reliability(incoming_source) > resolve_source_reliability(current_source):
                current["source"] = incoming_source

        incoming_evidence = str(incoming_fact.get("evidence") or "").strip()
        if incoming_evidence:
            current_evidence = str(current.get("evidence") or "").strip()
            if not current_evidence:
                current["evidence"] = incoming_evidence
            elif incoming_evidence not in current_evidence:
                current["evidence"] = f"{current_evidence} | {incoming_evidence}"

        incoming_evidence_ref = str(incoming_fact.get("evidence_ref") or "").strip()
        if incoming_evidence_ref:
            current_evidence_ref = str(current.get("evidence_ref") or "").strip()
            if not current_evidence_ref:
                current["evidence_ref"] = incoming_evidence_ref
            elif incoming_evidence_ref not in current_evidence_ref.split(" | "):
                current["evidence_ref"] = f"{current_evidence_ref} | {incoming_evidence_ref}"

        incoming_declared_confidence = str(incoming_fact.get("declared_confidence") or "").strip().lower()
        if incoming_declared_confidence:
            current_declared_confidence = str(current.get("declared_confidence") or "").strip().lower()
            if not current_declared_confidence:
                current["declared_confidence"] = incoming_declared_confidence
            elif incoming_declared_confidence not in current_declared_confidence.split(" | "):
                current["declared_confidence"] = f"{current_declared_confidence} | {incoming_declared_confidence}"

        incoming_template_fact_confidence = incoming_fact.get("template_fact_confidence")
        if incoming_template_fact_confidence is not None:
            current_template_fact_confidence = self._clamp_confidence(current.get("template_fact_confidence", 0.0))
            current["template_fact_confidence"] = max(
                current_template_fact_confidence,
                self._clamp_confidence(incoming_template_fact_confidence),
            )

        incoming_evidence_detail = incoming_fact.get("evidence_detail")
        if isinstance(incoming_evidence_detail, dict) and incoming_evidence_detail:
            if not isinstance(current.get("evidence_detail"), dict) or not current.get("evidence_detail"):
                current["evidence_detail"] = deepcopy(incoming_evidence_detail)

    def _find_conflicting_records(self, incoming_fact):
        fact_type = self._canonical_fact_type(incoming_fact.get("type"))
        if fact_type not in CONFLICT_SENSITIVE_FACT_TYPES:
            return []

        incoming_value = self._canonical_fact_value(fact_type, incoming_fact.get("value"))
        if not incoming_value:
            return []

        conflicts = []
        for record in self._records_by_type.get(fact_type, []):
            current_value = self._canonical_fact_value(fact_type, record["fact"].get("value"))
            if not current_value or current_value == incoming_value:
                continue
            conflicts.append(record)
        return conflicts

    def _apply_conflict_resolution(self, incoming_fact, conflicting_records):
        incoming_type = self._canonical_fact_type(incoming_fact.get("type"))
        incoming_value = self._canonical_fact_value(incoming_type, incoming_fact.get("value"))
        incoming_source = str(incoming_fact.get("source") or "unknown").strip()
        incoming_strength = resolve_source_reliability(incoming_source)

        strongest_conflict_strength = 0.0
        conflict_values = []

        for record in conflicting_records:
            current_fact = record["fact"]
            current_source = str(current_fact.get("source") or "unknown").strip()
            current_strength = resolve_source_reliability(current_source)
            strongest_conflict_strength = max(strongest_conflict_strength, current_strength)

            current_value = str(current_fact.get("value") or "").strip()
            if current_value:
                conflict_values.append(current_value)

            # Penalize weaker source more strongly; stronger source only lightly.
            if incoming_strength > current_strength:
                strength_gap = incoming_strength - current_strength
                factor = max(
                    CONFLICT_PENALTY_MIN_FACTOR,
                    0.9 - min(0.18, 0.45 * strength_gap),
                )
            elif incoming_strength < current_strength:
                factor = 0.96
            else:
                factor = 0.9

            current_conf = self._clamp_confidence(current_fact.get("confidence", 0.5))
            current_fact["confidence"] = self._clamp_confidence(current_conf * factor)
            current_fact["conflict"] = True

            existing_evidence = str(current_fact.get("evidence") or "").strip()
            conflict_tag = f"conflict:{incoming_type}={incoming_value}"
            if not existing_evidence:
                current_fact["evidence"] = conflict_tag
            elif conflict_tag not in existing_evidence:
                current_fact["evidence"] = f"{existing_evidence} | {conflict_tag}"

        incoming_conf = self._clamp_confidence(incoming_fact.get("confidence", 0.5))
        if incoming_strength < strongest_conflict_strength:
            incoming_gap = strongest_conflict_strength - incoming_strength
            factor = max(
                CONFLICT_PENALTY_MIN_FACTOR,
                0.88 - min(0.22, 0.5 * incoming_gap),
            )
            incoming_conf = self._clamp_confidence(incoming_conf * factor)
        else:
            incoming_conf = self._clamp_confidence(incoming_conf * 0.97)

        incoming_fact["confidence"] = incoming_conf
        incoming_fact["conflict"] = True

        conflict_value_text = "|".join(value for value in conflict_values if value) or "other"
        incoming_tag = f"conflict:{incoming_type}={conflict_value_text}"
        incoming_evidence = str(incoming_fact.get("evidence") or "").strip()
        if not incoming_evidence:
            incoming_fact["evidence"] = incoming_tag
        elif incoming_tag not in incoming_evidence:
            incoming_fact["evidence"] = f"{incoming_evidence} | {incoming_tag}"

    def _canonical_fact_type(self, raw_type):
        lowered = str(raw_type or "").strip().lower().replace("_", "-").replace(" ", "-")
        if not lowered:
            return ""
        return FACT_TYPE_ALIASES.get(lowered, lowered.replace("-", "_"))

    def _canonical_fact_value(self, fact_type, raw_value):
        text = str(raw_value or "").strip()
        if fact_type == "software_product":
            return normalize_product_fact_value(text)
        if fact_type == "vendor":
            return normalize_vendor_fact_value(text)
        if fact_type == "service":
            return normalize_service_fact_value(text)
        if fact_type == "protocol":
            return normalize_protocol_fact_value(text)
        if fact_type == "header":
            return normalize_header_feature(text)
        if fact_type == "path":
            return normalize_path_feature(text)
        if fact_type in LOWERCASE_VALUE_TYPES:
            return text.lower()
        return text

    def _clamp_confidence(self, value):
        try:
            numeric = float(value)
        except (TypeError, ValueError):
            numeric = 0.0

        numeric = max(0.0, min(numeric, 1.0))
        return min(numeric, self._confidence_cap if hasattr(self, "_confidence_cap") else DEFAULT_CONFIDENCE_CAP)
>>>>>>> 2dee6c78476454881e1511763dfd6ebe1c8aee4d
