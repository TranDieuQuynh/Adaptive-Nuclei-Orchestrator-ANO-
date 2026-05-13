"""Convert Nuclei YAML templates into ASMO Signature DB (nested JSON).

Usage:
    python signature_converter.py --templates-dir .\nuclei-small --output signatures.json

Output schema matches the spec in the prompt (PHẦN 3) and includes an additional
root key: "outputs" (required by ASMO to compute novelty and by NucleiRunner).

This module is Windows-friendly (Pathlib) and resilient:
- skips templates that fail to parse
- logs counts of found/converted/failed

Public API:
- convert_templates_to_signatures(templates_dir, output_path) -> list[TemplateSignature]
- load_signatures_from_json(path) -> list[TemplateSignature]
"""

from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

import yaml

from models import (
    Condition,
    ExecutionProfile,
    OutputMapping,
    Scope,
    SignatureInfo,
    SieveProfile,
    TemplateSignature,
)


IMPACT_BY_SEVERITY = {
    "info": 0.1,
    "low": 0.3,
    "medium": 0.5,
    "high": 0.8,
    "critical": 1.0,
}


def _setup_logger(name: str = "asmo.signature_converter") -> logging.Logger:
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger

    logger.setLevel(logging.INFO)
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
    logger.addHandler(handler)
    return logger


logger = _setup_logger()


def _coerce_tags(raw_tags: Any) -> List[str]:
    if raw_tags is None:
        return []

    if isinstance(raw_tags, str):
        parts = [p.strip() for p in raw_tags.replace(";", ",").split(",")]
        return [p for p in parts if p]

    if isinstance(raw_tags, list):
        out: List[str] = []
        for t in raw_tags:
            if t is None:
                continue
            if isinstance(t, str):
                if t.strip():
                    out.append(t.strip())
            else:
                out.append(str(t))
        return out

    return [str(raw_tags)]


def _has_any_key(doc: Dict[str, Any], keys: Iterable[str]) -> bool:
    for k in keys:
        if k in doc and doc.get(k) is not None:
            return True
    return False


def _infer_inputs(doc: Dict[str, Any]) -> List[str]:
    inputs: List[str] = []

    if _has_any_key(doc, ["http", "requests"]):
        inputs.append("url")

    if _has_any_key(doc, ["dns"]):
        inputs.append("domain")

    if _has_any_key(doc, ["network", "tcp"]):
        inputs.extend(["host", "port"])

    if _has_any_key(doc, ["ssl"]):
        inputs.append("host")

    if _has_any_key(doc, ["file"]):
        inputs.append("file")

    if not inputs:
        inputs = ["url"]

    # Dedup preserve order
    seen = set()
    out: List[str] = []
    for x in inputs:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


def _tag_set(tags: List[str]) -> set[str]:
    return {t.lower() for t in (tags or [])}


def _infer_conditions_from_tags(tags: List[str], severity: str) -> List[Condition]:
    tl = _tag_set(tags)

    # detect/tech templates: keep conditions empty so they can run in early iterations.
    if "detect" in tl or "tech" in tl:
        return []

    def _cond(tech: str) -> Condition:
        return Condition(type="tech", operator="eq", value=tech, weight=1.0)

    conditions: List[Condition] = []

    if "wordpress" in tl or "wp" in tl:
        conditions.append(_cond("wordpress"))

    if "php" in tl:
        conditions.append(_cond("php"))

    if "nginx" in tl:
        conditions.append(_cond("nginx"))

    if "apache" in tl:
        conditions.append(_cond("apache"))

    if "joomla" in tl:
        conditions.append(_cond("joomla"))

    if "drupal" in tl:
        conditions.append(_cond("drupal"))

    # cve/exposure tags do not create conditions.
    return conditions


def _infer_outputs(severity: str, tags: List[str]) -> List[str]:
    tl = _tag_set(tags)
    sev = (severity or "info").lower()

    outputs: List[str] = []

    if "detect" in tl or "tech" in tl:
        outputs.append("tech")

    if "version" in tl:
        outputs.append("version")

    if "cve" in tl or sev in {"high", "critical"}:
        outputs.extend(["vulnerability", "cve"])

    if "exposure" in tl:
        outputs.append("exposure")

    if not outputs and sev == "info":
        outputs.append("info")

    # Dedup
    seen = set()
    out: List[str] = []
    for x in outputs:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


def _count_requests(doc: Dict[str, Any]) -> int:
    total = 0

    http_block = doc.get("http")
    if isinstance(http_block, list):
        total += len(http_block)
    elif isinstance(http_block, dict):
        reqs = http_block.get("requests")
        if isinstance(reqs, list):
            total += len(reqs)

    reqs = doc.get("requests")
    if isinstance(reqs, list):
        total += len(reqs)

    for k in ["dns", "tcp", "network", "ssl", "file"]:
        block = doc.get(k)
        if isinstance(block, list):
            total += len(block)

    return total


def _infer_cost(severity: str, tags: List[str], doc: Dict[str, Any]) -> str:
    sev = (severity or "info").lower()
    tl = _tag_set(tags)

    cost = "normal"
    if sev == "info" or "detect" in tl or "tech" in tl:
        cost = "fast"

    if _count_requests(doc) > 5:
        cost = "slow"

    return cost


def _infer_risk(severity: str, tags: List[str]) -> str:
    sev = (severity or "info").lower()
    tl = _tag_set(tags)

    if "destructive" in tl:
        return "destructive"

    if "intrusive" in tl:
        return "intrusive"

    if sev in {"info", "low"}:
        return "safe"

    if sev == "medium":
        return "low"

    if sev in {"high", "critical"}:
        return "medium"

    return "medium"


def _timeout_for_cost(cost: str) -> int:
    cost = (cost or "normal").lower()
    if cost == "fast":
        return 10
    if cost == "slow":
        return 60
    if cost == "heavy":
        return 120
    return 30


def _infer_scope(doc: Dict[str, Any], execution_risk: str) -> Scope:
    protocol: Optional[str] = None
    allowed_ports: List[int] = []

    if _has_any_key(doc, ["http", "requests"]):
        protocol = "http"
        allowed_ports = [80, 443]

    return Scope(
        protocol=protocol,
        risk_level=str(execution_risk or "medium"),
        allowed_ports=allowed_ports,
    )


def _infer_output_mapping(tags: List[str], doc: Dict[str, Any]) -> List[OutputMapping]:
    tl = _tag_set(tags)
    mappings: List[OutputMapping] = []

    # Best-effort: if template contains extractor definitions, add source keys.
    # Nuclei JSONL doesn't always include extractor names per extracted item, so
    # ASMO also adds generic mapping entries based on tags.
    for block_key in ["http", "requests", "dns", "tcp", "network", "ssl", "file"]:
        block = doc.get(block_key)
        if isinstance(block, dict):
            extractors = block.get("extractors")
            if isinstance(extractors, list):
                for ex in extractors:
                    if isinstance(ex, dict) and ex.get("name"):
                        mappings.append(OutputMapping(source_key=str(ex["name"]), to_fact_type="extracted", confidence_boost=0.0))
        if isinstance(block, list):
            for item in block:
                if isinstance(item, dict):
                    extractors = item.get("extractors")
                    if isinstance(extractors, list):
                        for ex in extractors:
                            if isinstance(ex, dict) and ex.get("name"):
                                mappings.append(OutputMapping(source_key=str(ex["name"]), to_fact_type="extracted", confidence_boost=0.0))

    if "version" in tl:
        mappings.append(OutputMapping(source_key="extracted_version", to_fact_type="version", confidence_boost=0.1))

    if "cve" in tl:
        mappings.append(OutputMapping(source_key="matched_cve", to_fact_type="vulnerability", confidence_boost=0.2))

    # Dedup by (source_key,to_fact_type)
    seen = set()
    out: List[OutputMapping] = []
    for m in mappings:
        k = (m.source_key, m.to_fact_type)
        if k not in seen:
            seen.add(k)
            out.append(m)
    return out


def parse_template_file(path: Path) -> Tuple[Optional[TemplateSignature], Optional[str]]:
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
        doc = yaml.safe_load(text)
    except Exception as exc:
        return None, f"YAML read/parse failed: {exc}"

    if not isinstance(doc, dict):
        return None, "Template root is not a YAML object"

    template_id = doc.get("id")
    if not template_id:
        return None, "Missing template id"

    info_doc = doc.get("info") or {}
    if not isinstance(info_doc, dict):
        info_doc = {}

    name = str(info_doc.get("name") or template_id)
    severity = str(info_doc.get("severity") or "info").lower()
    tags = _coerce_tags(info_doc.get("tags"))
    author = info_doc.get("author")

    impact_score = float(IMPACT_BY_SEVERITY.get(severity, 0.1))

    inputs = _infer_inputs(doc)
    conditions = _infer_conditions_from_tags(tags, severity)

    cost = _infer_cost(severity, tags, doc)
    risk = _infer_risk(severity, tags)
    timeout = _timeout_for_cost(cost)

    scope = _infer_scope(doc, risk)

    outputs = _infer_outputs(severity, tags)
    output_mapping = _infer_output_mapping(tags, doc)

    sig = TemplateSignature(
        template_id=str(template_id),
        info=SignatureInfo(
            name=name,
            severity=severity,
            impact_score=impact_score,
            tags=tags,
        ),
        sieves=SieveProfile(
            inputs=inputs,
            conditions=conditions,
            scope=scope,
        ),
        execution=ExecutionProfile(
            cost=cost,
            risk=risk,
            timeout=timeout,
        ),
        outputs=outputs,
        output_mapping=output_mapping,
        meta={
            "author": str(author) if author is not None else "community",
            "last_updated": None,
            "template_path": str(path),
        },
    )

    return sig, None


def _condition_to_dict(c: Condition) -> Dict[str, Any]:
    d: Dict[str, Any] = {
        "type": c.type,
        "operator": c.operator,
        "value": c.value,
        "weight": c.weight,
    }
    if c.pattern is not None:
        d["pattern"] = c.pattern
    return d


def _scope_to_dict(s: Scope) -> Dict[str, Any]:
    return {
        "protocol": s.protocol,
        "risk_level": s.risk_level,
        "allowed_ports": list(s.allowed_ports or []),
    }


def _output_mapping_to_dict(m: OutputMapping) -> Dict[str, Any]:
    return {
        "source_key": m.source_key,
        "to_fact_type": m.to_fact_type,
        "confidence_boost": m.confidence_boost,
    }


def signature_to_dict(sig: TemplateSignature) -> Dict[str, Any]:
    return {
        "template_id": sig.template_id,
        "info": {
            "name": sig.info.name,
            "severity": sig.info.severity,
            "impact_score": sig.info.impact_score,
            "tags": list(sig.info.tags or []),
        },
        "sieves": {
            "inputs": list(sig.sieves.inputs or []),
            "conditions": [_condition_to_dict(c) for c in (sig.sieves.conditions or [])],
            "scope": _scope_to_dict(sig.sieves.scope),
        },
        "execution": {
            "cost": sig.execution.cost,
            "risk": sig.execution.risk,
            "timeout": sig.execution.timeout,
        },
        "outputs": list(sig.outputs or []),
        "output_mapping": [_output_mapping_to_dict(m) for m in (sig.output_mapping or [])],
        "meta": dict(sig.meta or {}),
    }


def convert_templates_to_signatures(templates_dir: str | Path, output_path: str | Path) -> List[TemplateSignature]:
    templates_root = Path(templates_dir)
    out_path = Path(output_path)

    yaml_files = sorted(list(templates_root.rglob("*.yaml")) + list(templates_root.rglob("*.yml")))

    logger.info(f"Found {len(yaml_files)} YAML templates under {templates_root}")

    signatures: List[TemplateSignature] = []
    failed = 0

    for p in yaml_files:
        sig, err = parse_template_file(p)
        if sig is None:
            failed += 1
            logger.warning(f"Skip {p}: {err}")
            continue
        signatures.append(sig)

    out_path.parent.mkdir(parents=True, exist_ok=True)

    payload = [signature_to_dict(s) for s in signatures]
    out_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

    logger.info(f"Converted signatures: {len(signatures)}")
    logger.info(f"Failed templates: {failed}")
    logger.info(f"Wrote: {out_path}")

    return signatures


def load_signatures_from_json(path: str | Path) -> List[TemplateSignature]:
    p = Path(path)
    raw = json.loads(p.read_text(encoding="utf-8"))

    if not isinstance(raw, list):
        raise ValueError("signatures.json must be a list")

    out: List[TemplateSignature] = []

    for item in raw:
        if not isinstance(item, dict):
            continue

        info = item.get("info") or {}
        sieves = item.get("sieves") or {}
        execution = item.get("execution") or {}

        scope_doc = sieves.get("scope") or {}
        scope = Scope(
            protocol=scope_doc.get("protocol"),
            risk_level=str(scope_doc.get("risk_level") or "medium"),
            allowed_ports=list(scope_doc.get("allowed_ports") or []),
        )

        conds: List[Condition] = []
        for c in sieves.get("conditions") or []:
            if not isinstance(c, dict):
                continue
            conds.append(
                Condition(
                    type=str(c.get("type")),
                    operator=str(c.get("operator")),
                    value=c.get("value"),
                    weight=float(c.get("weight", 1.0) or 1.0),
                    pattern=c.get("pattern"),
                )
            )

        mappings: List[OutputMapping] = []
        for m in item.get("output_mapping") or []:
            if not isinstance(m, dict):
                continue
            mappings.append(
                OutputMapping(
                    source_key=str(m.get("source_key")),
                    to_fact_type=str(m.get("to_fact_type")),
                    confidence_boost=float(m.get("confidence_boost", 0.0) or 0.0),
                )
            )

        out.append(
            TemplateSignature(
                template_id=str(item.get("template_id")),
                info=SignatureInfo(
                    name=str(info.get("name") or item.get("template_id")),
                    severity=str(info.get("severity") or "info"),
                    impact_score=float(info.get("impact_score", 0.1) or 0.1),
                    tags=list(info.get("tags") or []),
                ),
                sieves=SieveProfile(
                    inputs=list(sieves.get("inputs") or []),
                    conditions=conds,
                    scope=scope,
                ),
                execution=ExecutionProfile(
                    cost=str(execution.get("cost") or "normal"),
                    risk=str(execution.get("risk") or "medium"),
                    timeout=int(execution.get("timeout", 30) or 30),
                ),
                outputs=list(item.get("outputs") or []),
                output_mapping=mappings,
                meta=dict(item.get("meta") or {}),
            )
        )

    return out


def _build_arg_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description="Convert Nuclei templates into ASMO signatures.json")
    ap.add_argument("--templates-dir", required=True, help="Templates root directory (recursive)")
    ap.add_argument("--output", required=True, help="Output signatures JSON path")
    return ap


def main(argv: Optional[List[str]] = None) -> int:
    args = _build_arg_parser().parse_args(argv)
    convert_templates_to_signatures(args.templates_dir, args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
