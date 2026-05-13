from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple


def _setup_logger(name: str = "asmo.attack_graph") -> logging.Logger:
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger

    logger.setLevel(logging.INFO)
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
    logger.addHandler(handler)
    return logger


logger = _setup_logger()


def _dot_escape(text: str) -> str:
    s = str(text)
    s = s.replace("\\", "\\\\")
    s = s.replace('"', "\\\"")
    s = s.replace("\n", "\\n")
    s = s.replace("\r", "")
    return s


class AttackGraph:
    def __init__(self):
        self.nodes: Dict[str, Dict[str, Any]] = {}
        self.edges: List[Tuple[str, str]] = []
        self._edge_set: set[Tuple[str, str]] = set()
        self.edge_metadata: Dict[Tuple[str, str], Dict[str, Any]] = {}

    def _ensure_node(self, node_id: str, kind: str, label: str, shape: str, metadata: Dict[str, Any] | None = None) -> str:
        node = self.nodes.get(node_id)
        if node is None:
            self.nodes[node_id] = {
                "id": node_id,
                "kind": kind,
                "label": label,
                "shape": shape,
                "metadata": dict(metadata or {}),
            }
            return node_id

        existing_metadata = node.setdefault("metadata", {})
        if metadata:
            existing_metadata.update({k: v for k, v in metadata.items() if v is not None})
        node.setdefault("kind", kind)
        node.setdefault("label", label)
        node.setdefault("shape", shape)
        return node_id

    def _set_node_metadata(self, node_id: str, metadata: Dict[str, Any]) -> None:
        node = self.nodes.get(node_id)
        if node is None:
            return
        node_metadata = node.setdefault("metadata", {})
        for key, value in metadata.items():
            if value is not None:
                node_metadata[key] = value

    def _set_edge_metadata(self, src: str, dst: str, metadata: Dict[str, Any]) -> None:
        existing = self.edge_metadata.setdefault((src, dst), {})
        for key, value in metadata.items():
            if value is not None:
                existing[key] = value

    def add_fact_node(self, fact: Any) -> str:
        fact_type = getattr(fact, "type", "")
        value = getattr(fact, "value", "")
        node_id = f"fact:{fact_type}:{value}"
        metadata = {
            "confidence": getattr(fact, "confidence", None),
            "depth": getattr(fact, "discovery_depth", None),
            "source_template": (getattr(fact, "source", {}) or {}).get("template_id"),
        }
        self._ensure_node(node_id, "fact", f"{fact_type}:{value}", "ellipse", metadata)
        return node_id

    def add_template_node(self, template: Any, score: float | None = None, policy_result: str | None = None, status: str | None = None) -> str:
        template_id = getattr(template, "template_id", "")
        node_id = f"template:{template_id}"
        metadata = {
            "score": score,
            "policy": policy_result,
            "status": status,
        }
        self._ensure_node(node_id, "template", str(template_id), "box", metadata)
        return node_id

    def _add_edge(self, src: str, dst: str, metadata: Dict[str, Any] | None = None) -> None:
        e = (src, dst)
        if e in self._edge_set:
            if metadata:
                self._set_edge_metadata(src, dst, metadata)
            return
        self._edge_set.add(e)
        self.edges.append(e)
        if metadata:
            self._set_edge_metadata(src, dst, metadata)
        logger.info(f"[GRAPH] Added edge {src} -> {dst}")

    def add_execution(
        self,
        trigger_facts: Iterable[Any],
        template: Any,
        new_facts: Iterable[Any],
        template_score: float | None = None,
        policy_result: str | None = None,
        status: str | None = None,
    ) -> None:
        template_node = self.add_template_node(template, template_score, policy_result, status)

        for f in trigger_facts or []:
            src = self.add_fact_node(f)
            reason = None
            fact_type = str(getattr(f, "type", "") or "").lower()
            template_id = str(getattr(template, "template_id", "") or "").lower()
            if fact_type == "url" and template_id in {"wordpress-detect", "wordpress-passive-detection"}:
                reason = "url-based recon"
            elif fact_type == "tech":
                reason = "semantic match"
            elif isinstance(getattr(f, "metadata", None), dict):
                reason = f.metadata.get("inferred_from")
            if not reason:
                reason = "activated"
            self._add_edge(src, template_node, {"type": "activated", "reason": reason})

        for nf in new_facts or []:
            dst = self.add_fact_node(nf)
            self._set_node_metadata(dst, {
                "source_template": getattr(template, "template_id", None),
                "confidence": getattr(nf, "confidence", None),
                "depth": getattr(nf, "discovery_depth", None),
            })
            self._add_edge(template_node, dst, {"type": "produced", "confidence": getattr(nf, "confidence", None)})


    def export_dot(self, path: str) -> None:
        out_path = Path(path)
        out_path.parent.mkdir(parents=True, exist_ok=True)

        with out_path.open("w", encoding="utf-8", newline="\n") as f:
            f.write("digraph ASMO {\n")

            # Nodes
            for node_id in sorted(self.nodes.keys()):
                node = self.nodes[node_id]
                label = _dot_escape(node.get("label", ""))
                shape = node.get("shape", "ellipse")
                attrs = [f'label="{label}"', f"shape={shape}"]
                metadata = node.get("metadata", {}) or {}
                if node.get("kind") == "template":
                    status = str(metadata.get("status") or "").lower()
                    if status == "vetoed":
                        attrs.append("style=dashed")
                    else:
                        attrs.append("style=filled")
                f.write(f"  \"{_dot_escape(node_id)}\" [{', '.join(attrs)}];\n")

            f.write("\n")

            # Edges
            for src, dst in self.edges:
                meta = self.edge_metadata.get((src, dst), {})
                label = meta.get("type") or meta.get("reason") or ""
                label = _dot_escape(str(label)) if label else ""
                if label:
                    f.write(f"  \"{_dot_escape(src)}\" -> \"{_dot_escape(dst)}\" [label=\"{label}\"];\n")
                else:
                    f.write(f"  \"{_dot_escape(src)}\" -> \"{_dot_escape(dst)}\";\n")

            f.write("}\n")


    def export_json(self, path: str) -> None:
        out_path = Path(path)
        out_path.parent.mkdir(parents=True, exist_ok=True)

        payload = {
            "nodes": [
                {
                    "id": node.get("id"),
                    "type": node.get("kind"),
                    "label": node.get("label"),
                    "metadata": node.get("metadata", {}),
                }
                for node in self.nodes.values()
            ],
            "edges": [
                {
                    "source": s,
                    "target": d,
                    "type": (self.edge_metadata.get((s, d), {}) or {}).get("type"),
                    "metadata": self.edge_metadata.get((s, d), {}),
                }
                for (s, d) in self.edges
            ],
        }

        with out_path.open("w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)
