"""NucleiRunner: execute real Nuclei templates and convert JSONL output into Facts.

Requirements implemented (per prompt):
- calls nuclei via subprocess
- reads template path from template.meta["template_path"]
- selects target from Fact type "url"
- parses JSONL stdout
- resilient error handling (missing binary/template, timeout, JSON decode noise)
- produces Facts matching the normalized Fact schema (models.Fact)
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import subprocess
import time
from typing import Any, Dict, List, Optional

from blackboard import Blackboard
from models import Fact, OutputMapping, TemplateSignature


def _setup_logger(name: str = "asmo.nuclei") -> logging.Logger:
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger

    logger.setLevel(logging.INFO)
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
    logger.addHandler(handler)
    return logger


logger = _setup_logger()


def make_fact_id(fact_type: str, value: Any, template_id: Optional[str] = None) -> str:
    """Generate a stable-enough id for a new Fact.

    Includes current time to avoid collisions when creating many facts quickly.
    Blackboard still deduplicates by Fact.key().
    """

    raw = f"{fact_type}:{value}:{template_id}:{time.time()}".encode("utf-8", errors="ignore")
    return "f_" + hashlib.sha1(raw).hexdigest()[:10]


def _as_list(x: Any) -> List[Any]:
    if x is None:
        return []
    if isinstance(x, list):
        return x
    return [x]


def get_trigger_depth(template: TemplateSignature, B: Blackboard) -> int:
    """Max discovery_depth among facts relevant to this template's inputs/conditions."""

    max_depth = 0

    input_types = list(template.sieves.inputs or [])
    cond_types = [c.type for c in (template.sieves.conditions or []) if getattr(c, "type", None)]

    for t in set(input_types + cond_types):
        for fact in B.get_by_type(t):
            max_depth = max(max_depth, int(getattr(fact, "discovery_depth", 0)))

    return max_depth


def get_template_outputs(template: TemplateSignature) -> List[str]:
    return list(getattr(template, "outputs", None) or [])


def normalize_tag(tag: str) -> str:
    return str(tag or "").strip().lower().replace("_", "-")


def normalize_tech_value(value: str) -> str:
    v = str(value or "").strip().lower()
    if v == "wp":
        return "wordpress"
    return v


def _template_path_normalized(template: TemplateSignature) -> str:
    meta = template.meta or {}
    p = str(meta.get("template_path") or "")
    return p.replace("\\", "/").lower()


def is_theme_template(template: TemplateSignature) -> bool:
    tid = normalize_tag(template.template_id)
    p = _template_path_normalized(template)
    return ("/themes/" in p) or ("theme" in tid)


def is_plugin_template(template: TemplateSignature) -> bool:
    tid = normalize_tag(template.template_id)
    p = _template_path_normalized(template)
    return ("/plugins/" in p) or ("plugin" in tid)


def is_detect_template(template: TemplateSignature) -> bool:
    tid = str(template.template_id or "").lower()
    tags = {normalize_tag(t) for t in (template.info.tags or [])}
    outputs = set(get_template_outputs(template))
    return (
        "detect" in tid
        or "detection" in tid
        or "detect" in tags
        or "detection" in tags
        or "tech" in outputs
    )


GENERIC_TECH_TAGS = {
    "tech",
    "detect",
    "detection",
    "discovery",
    "http",
    "https",
    "misc",
    "exposure",
    "cve",
    "rce",
    "panel",
    "login",
    "default",
    "favicon",
    "fingerprint",
    "cms",
}


def infer_technology_name(template: TemplateSignature, result: Dict[str, Any]) -> tuple[Optional[str], bool]:
    """Infer technology name from a nuclei result.

    Returns: (tech_name, from_extracted_results)
    """

    template_id_norm = normalize_tag(template.template_id)
    # For theme/plugin templates (and wordpress-passive-detection), extracted results represent
    # theme/plugin names and should not be treated as technology names.
    if not (is_theme_template(template) or is_plugin_template(template) or template_id_norm == "wordpress-passive-detection"):
        extracted = _as_list(result.get("extracted-results") or result.get("extracted_results"))
        if extracted:
            for item in extracted:
                s = str(item).strip()
                if not s:
                    continue
                # Avoid treating versions as tech names (common in detect templates).
                if is_version_like(s):
                    continue
                if 1 <= len(s) <= 40:
                    return normalize_tech_value(s).replace("_", "-"), True

    tags = [normalize_tag(t) for t in (template.info.tags or [])]

    # Prefer explicit tech tags (excluding generic ones), but keep wordpress.
    for t in tags:
        if not t:
            continue
        if t == "wordpress":
            return "wordpress", False
        if t in GENERIC_TECH_TAGS:
            continue
        if re.fullmatch(r"[a-z0-9][a-z0-9\-\.]{1,60}", t):
            return normalize_tech_value(t), False

    tid = normalize_tag(template.template_id)
    for suffix in ["-detect", "-detection", "-technology", "-fingerprint"]:
        if tid.endswith(suffix):
            tid = tid[: -len(suffix)]
            break
    tid = tid.strip("-")
    return (normalize_tech_value(tid) if tid else None), False


VERSION_RE = re.compile(r"\d+(?:\.\d+){0,3}")


def is_version_like(text: str) -> bool:
    text = str(text or "").strip()
    if not text:
        return False
    return bool(VERSION_RE.fullmatch(text) or VERSION_RE.search(text))


CVE_RE = re.compile(r"(?i)\bCVE-\d{4}-\d+\b")


def extract_cve_ids(texts: List[str]) -> List[str]:
    found: List[str] = []
    for t in texts:
        for m in CVE_RE.findall(str(t or "")):
            found.append(m.upper())
    # Dedup preserve order
    seen = set()
    out: List[str] = []
    for c in found:
        if c not in seen:
            seen.add(c)
            out.append(c)
    return out


def _severity_confidence(sev: str) -> float:
    sev = (sev or "info").lower()
    if sev == "critical":
        return 0.9
    if sev == "high":
        return 0.85
    if sev == "medium":
        return 0.75
    return 0.7


def parse_nuclei_result(
    result: Dict[str, Any],
    template: TemplateSignature,
    B: Blackboard,
    target: str,
) -> List[Fact]:
    """Convert one Nuclei JSON result object into ASMO Facts."""

    rid = result.get("template-id") or result.get("template_id")
    template_id = str(rid or template.template_id)

    matched_at = result.get("matched-at") or result.get("matched_at")
    matcher_name = result.get("matcher-name") or result.get("matcher_name")

    # Prefer severity from signature schema
    severity = str(getattr(getattr(template, "info", None), "severity", "info") or "info").lower()
    trigger_depth = get_trigger_depth(template, B)
    discovery_depth = trigger_depth + 1

    extracted_results = _as_list(result.get("extracted-results") or result.get("extracted_results"))
    outputs = set(get_template_outputs(template))
    tags = list(template.info.tags or [])
    tl = {normalize_tag(t) for t in tags}

    consumed_extracted: set[str] = set()

    facts: List[Fact] = []

    def _best_extracted_value() -> Optional[str]:
        for item in extracted_results:
            s = str(item).strip()
            if s and not is_version_like(s):
                return normalize_tag(s)
        return None

    def _mk_fact(
        fact_type: str,
        value: Any,
        confidence: float,
        certainty: str,
        metadata_extra: Optional[Dict[str, Any]] = None,
    ) -> Fact:
        md = {
            "certainty": certainty,
            "matched_at": matched_at,
            "matcher_name": matcher_name,
            "raw_result": result,
        }
        if metadata_extra:
            md.update(metadata_extra)

        return Fact(
            id=make_fact_id(fact_type, value, template_id=template.template_id),
            type=fact_type,
            value=value,
            confidence=float(confidence),
            source={"tool": "nuclei", "template_id": template.template_id},
            target=target,
            discovery_depth=discovery_depth,
            ttl=3,
            tags=tags,
            metadata=md,
        )

    # CASE A: Template match
    if rid:
        facts.append(
            _mk_fact(
                "template_match",
                template_id,
                0.8,
                "medium",
            )
        )

    template_id_lower = template_id.lower()
    best_extracted = _best_extracted_value()

    def _add_template_fallback_fact(
        fact_type: str,
        value: Any,
        confidence: float = 0.8,
        certainty: str = "medium",
    ) -> None:
        facts.append(
            _mk_fact(
                fact_type,
                value,
                confidence,
                certainty,
                {"inferred_from": "template_id_fallback"},
            )
        )

    if rid:
        if template_id_lower in {"wordpress-detect", "wordpress-passive-detection"}:
            _add_template_fallback_fact("tech", "wordpress", 0.9, "high")
        elif template_id_lower == "wordpress-readme-file":
            _add_template_fallback_fact("exposure", "readme", 0.85, "high")
            _add_template_fallback_fact("tech", "wordpress", 0.8, "medium")
        elif template_id_lower.startswith("graphql-"):
            _add_template_fallback_fact("tech", "graphql", 0.85, "high")
        elif template_id_lower == "phppgadmin-version":
            _add_template_fallback_fact("tech", "phppgadmin", 0.85, "high")
        elif template_id_lower == "xampp-phpinfo-detect":
            _add_template_fallback_fact("tech", "xampp", 0.85, "high")
            _add_template_fallback_fact("exposure", "phpinfo", 0.85, "high")
        elif "theme-detect" in template_id_lower and best_extracted:
            _add_template_fallback_fact("theme", best_extracted, 0.85, "high")
        elif "plugin-detect" in template_id_lower and best_extracted:
            _add_template_fallback_fact("plugin", best_extracted, 0.85, "high")

    # CASE B: Detect -> tech
    if rid and is_detect_template(template):
        tech, tech_from_extracted = infer_technology_name(template, result)
        if tech:
            tech_conf = 0.85 if tech_from_extracted else 0.70
            facts.append(
                _mk_fact(
                    "tech",
                    normalize_tech_value(tech),
                    tech_conf,
                    "high" if tech_from_extracted else "medium",
                    {"inferred_from": "detect_template_match"},
                )
            )

    # CASE B2: Theme/Plugin from extracted results
    template_id_norm = normalize_tag(template.template_id)
    theme_template = is_theme_template(template)
    plugin_template = is_plugin_template(template)

    if extracted_results:
        # wordpress-passive-detection: extracted theme name
        if template_id_norm == "wordpress-passive-detection":
            for item in extracted_results:
                s = str(item).strip()
                if not s or is_version_like(s):
                    continue
                consumed_extracted.add(s)
                facts.append(
                    _mk_fact(
                        "theme",
                        normalize_tag(s),
                        0.85,
                        "high",
                        {"inferred_from": "extracted_results"},
                    )
                )

        # theme/plugin templates: extracted results -> theme/plugin facts
        elif theme_template or plugin_template:
            out_type = "theme" if theme_template else "plugin"
            for item in extracted_results:
                s = str(item).strip()
                if not s or is_version_like(s):
                    continue
                consumed_extracted.add(s)
                facts.append(
                    _mk_fact(
                        out_type,
                        normalize_tag(s),
                        0.85,
                        "high",
                        {"inferred_from": "extracted_results"},
                    )
                )

    # CASE C: Version extraction
    version_boost = 0.0
    for m in (template.output_mapping or []):
        if str(m.to_fact_type).lower() == "version":
            version_boost = max(version_boost, float(m.confidence_boost or 0.0))

    if extracted_results:
        for item in extracted_results:
            s = str(item).strip()
            if not s:
                continue

            # version-like
            if is_version_like(s):
                m = VERSION_RE.search(s)
                version_value = m.group(0) if m else s
                consumed_extracted.add(s)
                facts.append(
                    _mk_fact(
                        "version",
                        version_value,
                        min(0.99, 0.85 + version_boost),
                        "high",
                        {
                            "inferred_from": "extracted_results",
                            "raw_extracted": s,
                        },
                    )
                )
                continue

    # CASE D: Vulnerability / CVE
    vuln_tags = {"cve", "rce", "sqli", "xss", "lfi", "rfi"}
    if (
        severity in {"high", "critical"}
        or bool(tl.intersection(vuln_tags))
        or "vulnerability" in outputs
    ):
        vuln_conf = _severity_confidence(severity)
        facts.append(
            _mk_fact(
                "vulnerability",
                template.template_id,
                vuln_conf,
                "high" if severity in {"high", "critical"} else "medium",
                {"severity": severity},
            )
        )

        cve_texts: List[str] = [template.template_id] + tags + [json.dumps(result, ensure_ascii=False)]
        for cve in extract_cve_ids(cve_texts):
            facts.append(_mk_fact("cve", cve, vuln_conf, "high", {"severity": severity}))

    # CASE E: Exposure
    if "exposure" in tl or "exposure" in outputs:
        facts.append(_mk_fact("exposure", template.template_id, 0.8, "medium"))

    # CASE F: Generic extracted
    for item in extracted_results:
        s = str(item).strip()
        if not s:
            continue
        if s in consumed_extracted:
            continue
        facts.append(
            _mk_fact(
                "extracted",
                s,
                0.7,
                "medium",
                {"raw_extracted": s},
            )
        )

    # Dedup facts by key within the same result (keep max confidence)
    best_by_key: Dict[Any, Fact] = {}
    for f in facts:
        k = f.key()
        old = best_by_key.get(k)
        if old is None or f.confidence > old.confidence:
            best_by_key[k] = f

    return list(best_by_key.values())


class NucleiRunner:
    def __init__(
        self,
        nuclei_bin: str = r"D:\Nuclei\nuclei_3.7.1_windows_amd64\nuclei.exe",
        timeout: int = 60,
        verbose: bool = True,
        demo_mode: bool = False,
    ):
        self.nuclei_bin = nuclei_bin
        self.timeout = int(timeout)
        self.verbose = bool(verbose)
        self.demo_mode = bool(demo_mode)

    def _select_target(self, B: Blackboard) -> str:
        url_facts = list(B.get_by_type("url"))
        if not url_facts:
            raise ValueError("No url fact found in Blackboard")
        return str(url_facts[0].value)

    def _template_path(self, template: TemplateSignature) -> str:
        meta = template.meta or {}
        template_path = meta.get("template_path")
        if not template_path:
            raise ValueError(f"Missing meta.template_path for template {template.template_id}")
        return str(template_path)

    def run(self, template: TemplateSignature, B: Blackboard, context: Optional[Dict[str, Any]] = None) -> List[Fact]:
        context = context or {}
        demo_mode = bool(context.get("demo_mode", self.demo_mode))

        try:
            target = self._select_target(B)
        except ValueError as exc:
            logger.error(str(exc))
            return []

        template_path = self._template_path(template)
        if not os.path.exists(template_path):
            logger.error(f"Template file not found: {template_path}")
            return []

        template_tags = list(getattr(getattr(template, "info", None), "tags", None) or [])

        cmd = [
            self.nuclei_bin,
            "-u",
            target,
            "-t",
            template_path,
            "-jsonl",
            "-silent",
        ]

        logger.info(f"[NUCLEI-CMD] {' '.join(cmd)}")
        timeout_used = self.timeout
        start_time = time.time()
        execution_duration = None
        template_status = "unknown"
        timeout_reason = None
        stdout = ""
        stderr = ""
        completed = None

        logger.info(f"[NUCLEI-START] {template.template_id}")
        try:
            completed = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout_used,
            )
            execution_duration = time.time() - start_time
            stdout = completed.stdout or ""
            stderr = completed.stderr or ""
            if completed.returncode != 0:
                logger.error(f"[NUCLEI-ERROR] code={completed.returncode} stderr={stderr.strip()}")
                template_status = "failed"
            else:
                template_status = "success"
        except FileNotFoundError:
            logger.error("[NUCLEI-ERROR] nuclei binary not found")
            template_status = "failed"
            return []
        except subprocess.TimeoutExpired:
            execution_duration = time.time() - start_time
            logger.error(f"[NUCLEI-TIMEOUT] {template.template_id} after {timeout_used}s")
            template_status = "timeout"
            timeout_reason = f"timeout after {timeout_used}s"
            # orchestration continues, return failed result
            logger.info(f"[NUCLEI-END] {template.template_id} status=timeout duration={execution_duration:.2f}s")
            return []
        except Exception as exc:
            execution_duration = time.time() - start_time
            logger.error(f"[NUCLEI-ERROR] {exc}")
            template_status = "failed"
            logger.info(f"[NUCLEI-END] {template.template_id} status=failed duration={execution_duration:.2f}s")
            return []

        logger.info(f"[NUCLEI-END] {template.template_id} status={template_status} duration={execution_duration:.2f}s")

        if template_status == "failed":
            # orchestration continues, do not raise
            return []

        any_line = False
        facts: List[Fact] = []
        matched_logged = False

        for raw_line in stdout.splitlines():
            line = raw_line.strip()
            if not line:
                continue

            any_line = True

            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                logger.warning(f"Skip non-JSON line: {line[:200]}")
                continue

            if not isinstance(obj, dict):
                logger.warning("Skip JSONL item that is not an object")
                continue

            try:
                if self.verbose and (obj.get("template-id") or obj.get("template_id")) and not matched_logged:
                    logger.info(f"[MATCH] {template.template_id} matched")
                    matched_logged = True

                new_facts = parse_nuclei_result(obj, template, B, target)
                if self.verbose:
                    for f in new_facts:
                        logger.info(f"[FACT] {f.type}={f.value} confidence={f.confidence:.2f}")

                facts.extend(new_facts)
            except Exception as exc:
                logger.warning(f"Failed to parse nuclei result into facts: {exc}")

        if not any_line:
            if demo_mode:
                template_id_lower = str(template.template_id or "").lower()
                if template_id_lower in {"wordpress-detect", "wordpress-passive-detection", "wordpress-readme-file"}:
                    trigger_depth = get_trigger_depth(template, B)
                    discovery_depth = trigger_depth + 1
                    logger.info(
                        f"[DEMO-FALLBACK] {template.template_id} produced tech:wordpress because demo-mode enabled"
                    )
                    fallback_facts = [
                        Fact(
                            id=make_fact_id("template_match", template.template_id, template.template_id),
                            type="template_match",
                            value=template.template_id,
                            confidence=0.6,
                            source={"tool": "nuclei", "template_id": template.template_id, "mode": "demo_fallback"},
                            target=target,
                            discovery_depth=discovery_depth,
                            ttl=3,
                            tags=template_tags,
                            metadata={
                                "certainty": "medium",
                                "inferred_from": "demo_fallback",
                                "matched_at": None,
                                "matcher_name": None,
                                "raw_result": {},
                            },
                        ),
                        Fact(
                            id=make_fact_id("tech", "wordpress", template.template_id),
                            type="tech",
                            value="wordpress",
                            confidence=0.6,
                            source={"tool": "nuclei", "template_id": template.template_id, "mode": "demo_fallback"},
                            target=target,
                            discovery_depth=discovery_depth,
                            ttl=3,
                            tags=template_tags,
                            metadata={
                                "certainty": "medium",
                                "inferred_from": "demo_fallback",
                                "matched_at": None,
                                "matcher_name": None,
                                "raw_result": {},
                            },
                        ),
                    ]
                    logger.info(
                        f"[FACT-EXTRACT] {template.template_id} "
                        + ", ".join(f"{f.type}:{f.value}" for f in fallback_facts)
                    )
                    return fallback_facts

            if self.verbose:
                logger.info(f"[NO-NEW-FACTS] {template.template_id}")
            return []

        if self.verbose:
            if facts:
                extracted_summary = ", ".join(f"{f.type}:{f.value}" for f in facts)
                logger.info(f"[FACT-EXTRACT] {template.template_id} {extracted_summary}")
            else:
                logger.info(f"[NO-NEW-FACTS] {template.template_id}")

        return facts
