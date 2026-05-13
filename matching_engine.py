"""Template matching engine.

The engine maps newly-added facts to candidate templates (via SignatureIndex)
then applies semantic gating, dedup, and scoring.
"""

from __future__ import annotations

import logging

from index import SignatureIndex
from models import MatchDecision, SieveDecision
from operators import match_operator
from scoring import compute_final_score


STRATEGIC_FACT_TYPES = {
    "url",
    "protocol",
    "tech",
    "version",
    "vulnerability",
    "cve",
    "path",
    "panel",
}

URL_GENERIC_TEMPLATE_IDS = {
    "wordpress-detect",
    "wordpress-passive-detection",
}


def _setup_logger(name: str = "asmo.matching") -> logging.Logger:
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger
    logger.setLevel(logging.INFO)
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
    logger.addHandler(handler)
    return logger


logger = _setup_logger()


def _normalize_text(value) -> str:
    return str(value or "").strip().lower()


def evaluate_condition(condition, fact):
    if condition is None or fact is None:
        return False, "missing condition or fact"

    condition_type = _normalize_text(getattr(condition, "type", ""))
    fact_type = _normalize_text(getattr(fact, "type", ""))
    if condition_type != fact_type:
        return False, f"{fact_type}:{getattr(fact, 'value', '')} != {condition_type}:{getattr(condition, 'value', '')}"

    operator = _normalize_text(getattr(condition, "operator", "eq"))
    fact_value = getattr(fact, "value", None)
    condition_value = getattr(condition, "value", None)

    if operator == "exists":
        return True, f"{fact_type}:{fact_value} exists"

    if operator == "eq":
        matched = _normalize_text(fact_value) == _normalize_text(condition_value)
        return matched, f"{fact_type}:{fact_value} {'==' if matched else '!='} {fact_type}:{condition_value}"

    if operator == "contains":
        matched = _normalize_text(condition_value) in _normalize_text(fact_value)
        return matched, f"{fact_type}:{fact_value} {'contains' if matched else 'does not contain'} {condition_value}"

    if operator == "startswith":
        matched = _normalize_text(fact_value).startswith(_normalize_text(condition_value))
        return matched, f"{fact_type}:{fact_value} {'startswith' if matched else 'does not start with'} {condition_value}"

    if operator == "regex":
        import re

        pattern = getattr(condition, "pattern", None) or str(condition_value or "")
        matched = bool(pattern) and bool(re.search(pattern, str(fact_value or ""), re.IGNORECASE))
        return matched, f"{fact_type}:{fact_value} {'matches' if matched else 'does not match'} /{pattern}/"

    return False, f"unsupported operator {operator}"


def _condition_matches_blackboard(condition, B):
    for fact in B.get_by_type(getattr(condition, "type", None)):
        matched, reason = evaluate_condition(condition, fact)
        if matched:
            logger.info(f"[CONDITION-MATCH]\n{reason}")
            return True
    return False


def _condition_label(condition) -> str:
    condition_type = _normalize_text(getattr(condition, "type", ""))
    operator = _normalize_text(getattr(condition, "operator", "eq"))
    value = getattr(condition, "value", None)
    if operator == "exists":
        return condition_type
    if value is None:
        return condition_type
    return f"{condition_type}:{value}"


def _format_missing_conditions(conditions) -> str:
    missing = []
    seen = set()
    for condition in conditions or []:
        label = _condition_label(condition)
        if label and label not in seen:
            seen.add(label)
            missing.append(label)
    return ", ".join(missing)


class MatchingEngine:
    def __init__(self, templates, policy, k_latest: int = 10):
        self.index = SignatureIndex(templates)
        self.policy = policy
        self.executed = set()
        self.k_latest = getattr(policy, "k_latest", 10) if hasattr(policy, "k_latest") else k_latest

    def match_latest_facts(self, blackboard):
        """Return matches for the latest facts in the blackboard."""
        latest_facts = blackboard.get_latest(self.k_latest)
        results = []
        for fact in latest_facts:
            matches = self.match_from_fact(fact, blackboard)
            for template, score in matches:
                results.append((template, score, fact))
        return results

    def dedup_key(self, template, B) -> str:
        parts = [template.template_id]

        for input_type in (template.sieves.inputs or []):
            for fact in B.get_by_type(input_type):
                parts.append(f"{fact.type}:{fact.value}:{fact.target}")

        for cond in (template.sieves.conditions or []):
            for fact in B.get_by_type(cond.type):
                parts.append(f"{fact.type}:{fact.value}:{fact.target}")

        return "|".join(sorted(parts))

    def already_executed(self, template, B) -> bool:
        return self.dedup_key(template, B) in self.executed

    def mark_executed(self, template, B) -> None:
        self.executed.add(self.dedup_key(template, B))

    def _is_wordpress_family(self, template) -> bool:
        template_id = _normalize_text(getattr(template, "template_id", ""))
        return (
            template_id.startswith("wordpress-")
            or template_id.startswith("wp-")
        )

    def _has_fact(self, B, fact_type: str, fact_value: str | None = None) -> bool:
        for fact in B.get_by_type(fact_type):
            if fact_value is None or _normalize_text(getattr(fact, "value", "")) == _normalize_text(fact_value):
                return True
        return False

    def _semantic_match_allowed(self, template, B, fact):
        preconditions = list(getattr(template, "preconditions", None) or [])
        if preconditions:
            missing = []
            for cond in preconditions:
                if not _condition_matches_blackboard(cond, B):
                    missing.append(_condition_label(cond))
            if missing:
                return False, f"missing {', '.join(missing)}"
            return True, "semantic match"

        conditions = list(getattr(getattr(template, "sieves", None), "conditions", None) or [])
        if conditions:
            missing = []
            for cond in conditions:
                if not _condition_matches_blackboard(cond, B):
                    missing.append(_condition_label(cond))
            if missing:
                return False, f"missing {_format_missing_conditions([c for c in conditions if _condition_label(c) in set(missing)])}"
            return True, "semantic match"

        if getattr(fact, "type", None) == "url":
            if _normalize_text(getattr(template, "template_id", "")) in URL_GENERIC_TEMPLATE_IDS:
                return True, "url-based recon"
            return False, "missing semantic precondition"

        if getattr(fact, "type", None) == "tech" and _normalize_text(getattr(fact, "value", "")) == "wordpress":
            if self._is_wordpress_family(template):
                return True, "semantic match"

        if self._is_wordpress_family(template) and self._has_fact(B, "tech", "wordpress"):
            return True, "semantic match"

        return False, "missing tech:wordpress"

    def _candidate_templates(self, fact, B):
        candidates = {template.template_id: template for template in self.index.lookup(fact)}

        if getattr(fact, "type", None) == "tech" and _normalize_text(getattr(fact, "value", "")) == "wordpress":
            for template in self.index.templates.values():
                if template.template_id in candidates:
                    continue
                if not self._is_wordpress_family(template):
                    continue
                if (template.sieves.inputs or []) and "url" not in (template.sieves.inputs or []):
                    continue
                candidates[template.template_id] = template

        return list(candidates.values())

    # --- Modular sieve functions ---
    def input_sieve(self, template, B):
        required = template.sieves.inputs or []
        if B.has_all_types(required):
            return SieveDecision(True, "all required inputs present", "input_sieve")
        missing = [t for t in required if not B.has_type(t)]
        return SieveDecision(False, f"missing input(s): {missing}", "input_sieve")

    def condition_sieve(self, template, B, fact=None):
        allowed, reason = self._semantic_match_allowed(template, B, fact)
        return SieveDecision(allowed, reason, "condition_sieve")

    def dedup_sieve(self, template, B):
        if not self.already_executed(template, B):
            return SieveDecision(True, "not executed before", "dedup_sieve")
        return SieveDecision(False, "already executed in this context", "dedup_sieve")

    def depth_sieve(self, template, B):
        depth_limit = getattr(template, "depth_limit", 0)
        if not depth_limit:
            return SieveDecision(True, "no depth_limit set", "depth_sieve")
        max_depth = 0
        for t in (template.sieves.inputs or []):
            for f in B.get_by_type(t):
                max_depth = max(max_depth, getattr(f, "discovery_depth", 0))
        for c in (template.sieves.conditions or []):
            for f in B.get_by_type(getattr(c, "type", None)):
                max_depth = max(max_depth, getattr(f, "discovery_depth", 0))
        if max_depth > depth_limit:
            return SieveDecision(False, f"current_depth {max_depth} > depth_limit {depth_limit}", "depth_sieve")
        return SieveDecision(True, f"depth {max_depth} within limit {depth_limit}", "depth_sieve")

    def risk_sieve(self, template, B):
        risk = getattr(template, "risk", 0.0)
        threshold = getattr(self.policy, "risk_threshold", 0.6)
        if not risk:
            return SieveDecision(True, "no risk set", "risk_sieve")
        if risk > threshold:
            return SieveDecision(False, f"risk {risk} > threshold {threshold}", "risk_sieve")
        return SieveDecision(True, f"risk {risk} within threshold {threshold}", "risk_sieve")

    def scope_sieve(self, template, B):
        return SieveDecision(True, "scope not enforced", "scope_sieve")

    def _score_template(self, template, fact, B):
        return compute_final_score(
            template,
            B,
            self.policy,
            index=self.index,
            all_templates=list(self.index.templates.values()),
            trigger_fact=fact,
        )

    def match_from_fact(self, fact, B):
        """Backward-compatible match list with explainable logs."""
        if fact.type not in STRATEGIC_FACT_TYPES:
            return []

        candidates = self._candidate_templates(fact, B)
        results = []

        for template in candidates:
            logger.info(f"[CANDIDATE]{fact.type}:{fact.value} -> {template.template_id}")

            sieve_results = []
            for sieve_name, sieve_fn in [
                ("input", self.input_sieve),
                ("condition", self.condition_sieve),
                ("dedup", self.dedup_sieve),
                ("depth", self.depth_sieve),
                ("risk", self.risk_sieve),
                ("scope", self.scope_sieve),
            ]:
                if sieve_name == "condition":
                    sieve_dec = sieve_fn(template, B, fact)
                else:
                    sieve_dec = sieve_fn(template, B)
                sieve_results.append(sieve_dec)
                if not sieve_dec.accepted:
                    if sieve_dec.reason != "missing semantic precondition":
                        logger.info(f"[SIEVE-REJECT]{template.template_id}:{sieve_dec.reason}")
                    break

            if not all(s.accepted for s in sieve_results):
                reject_reason = next((s.reason for s in sieve_results if not s.accepted), "missing semantic precondition")
                if reject_reason.startswith("missing"):
                    logger.info(f"[MATCH-REJECT]\n{template.template_id}:\n{reject_reason}")
                continue

            score = self._score_template(template, fact, B)

            if score != float("-inf"):
                if getattr(fact, "type", None) == "url" and _normalize_text(getattr(template, "template_id", "")) in URL_GENERIC_TEMPLATE_IDS:
                    logger.info(f"[GENERIC-MATCH] url-based recon {template.template_id} score={score:.4f}")
                else:
                    logger.info(f"[MATCH] semantic match {template.template_id} score={score:.4f}")
                results.append((template, score))
            else:
                logger.info(f"[MATCH-REJECT]{template.template_id}:score vetoed")

        return results

    def match_from_fact_explain(self, fact, B):
        """Return MatchDecision objects for each candidate template."""
        if fact.type not in STRATEGIC_FACT_TYPES:
            return []

        candidates = self._candidate_templates(fact, B)
        results = []

        for template in candidates:
            sieve_results = []
            failed_sieves = []
            for sieve_name, sieve_fn in [
                ("input", self.input_sieve),
                ("condition", self.condition_sieve),
                ("dedup", self.dedup_sieve),
                ("depth", self.depth_sieve),
                ("risk", self.risk_sieve),
                ("scope", self.scope_sieve),
            ]:
                if sieve_name == "condition":
                    sieve_dec = sieve_fn(template, B, fact)
                else:
                    sieve_dec = sieve_fn(template, B)
                sieve_results.append(sieve_dec)
                if not sieve_dec.accepted:
                    failed_sieves.append(sieve_dec)
                    break

            score = self._score_template(template, fact, B)
            matched = all(s.accepted for s in sieve_results) and score != float("-inf")
            reject_reason = next((s.reason for s in sieve_results if not s.accepted), "")
            if reject_reason.startswith("missing"):
                logger.info(f"[MATCH-REJECT]\n{template.template_id}:\n{reject_reason}")
            reason = "; ".join([s.reason for s in sieve_results if not s.accepted])
            results.append(
                MatchDecision(
                    matched=matched,
                    reason=reason,
                    score=score,
                    breakdown=None,
                    trigger_fact=fact,
                    failed_sieves=failed_sieves,
                )
            )
        return results
