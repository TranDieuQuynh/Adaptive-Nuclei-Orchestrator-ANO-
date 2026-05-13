def compute_chain_value(template, index=None, all_templates=None, B=None) -> float:
    """Estimate how many new templates this template could unlock."""

    outputs = {_normalize_text(out) for out in (getattr(template, "outputs", []) or []) if _normalize_text(out)}
    if not outputs or not all_templates:
        return 0.0

    current_types = {getattr(fact, "type", None) for fact in (B.all_facts() if B is not None else []) if getattr(fact, "type", None)}
    unlocked = 0

    for other in all_templates:
        if getattr(other, "template_id", None) == getattr(template, "template_id", None):
            continue

        required_types = set(getattr(getattr(other, "sieves", None), "inputs", None) or [])
        required_types.update(
            getattr(cond, "type", None)
            for cond in (getattr(getattr(other, "sieves", None), "conditions", None) or [])
            if getattr(cond, "type", None)
        )
        required_types.update(
            getattr(cond, "type", None)
            for cond in (getattr(other, "preconditions", None) or [])
            if getattr(cond, "type", None)
        )
        required_types = {_normalize_text(t_type) for t_type in required_types if _normalize_text(t_type)}

        if not required_types:
            continue

        if required_types <= current_types:
            continue

        if required_types <= (current_types | outputs):
            unlocked += 1

    return min(1.0, unlocked / max(1, len(all_templates)))

def compute_cost_penalty(template) -> float:
    cost = str(getattr(getattr(template, "execution", None), "cost", "normal")).lower()
    return COST.get(cost, 0.4)

def compute_risk_penalty(template) -> float:
    risk = str(getattr(getattr(template, "execution", None), "risk", "medium")).lower()
    return RISK.get(risk, 0.5)

def compute_depth_penalty(template, B, current_depth=None) -> float:
    depth_limit = getattr(template, "depth_limit", 0)
    max_depth = 0
    for t in (getattr(getattr(template, "sieves", None), "inputs", None) or []):
        for f in B.get_by_type(t):
            max_depth = max(max_depth, getattr(f, "discovery_depth", 0))
    for c in (getattr(getattr(template, "sieves", None), "conditions", None) or []):
        for f in B.get_by_type(getattr(c, "type", None)):
            max_depth = max(max_depth, getattr(f, "discovery_depth", 0))
    if current_depth is not None:
        max_depth = max(max_depth, current_depth)
    # Penalty nhẹ: mỗi depth vượt 1 cộng 0.05
    return 0.05 * max_depth

def compute_historical_bonus(template, historical_stats=None) -> float:
    # Hook adaptive: nếu template fail nhiều thì giảm, thành công thì tăng
    if not historical_stats:
        return 0.0
    tid = getattr(template, "template_id", None)
    if not tid:
        return 0.0
    succ = historical_stats.get(tid, {}).get("success", 0)
    fail = historical_stats.get(tid, {}).get("fail", 0)
    # Mỗi success tăng 0.01, mỗi fail giảm 0.02, clamp [-0.2, 0.2]
    bonus = min(0.2, max(-0.2, 0.01 * succ - 0.02 * fail))
    return bonus


# Ensure compute_impact is defined for scoring breakdown
def compute_impact(template, B) -> float:
    severity = str(getattr(getattr(template, "info", None), "severity", "info")).lower()
    return SEVERITY.get(severity, 0.1)
"""Scoring utilities for ASMO.

This module intentionally stays lightweight: it provides a few interpretable
metrics that the matching engine uses to rank templates.
"""

from operators import match_operator
from models import ScoringBreakdown
import logging
def _setup_logger(name: str = "asmo.scoring") -> logging.Logger:
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger
    logger.setLevel(logging.INFO)
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
    logger.addHandler(handler)
    return logger

logger = _setup_logger()

SEVERITY = {
    "info": 0.10,
    "low": 0.25,
    "medium": 0.50,
    "high": 0.80,
    "critical": 1.00,
}

COST = {
    "fast": 0.10,
    "normal": 0.40,
    "slow": 0.70,
}

RISK = {
    "safe": 0.10,
    "medium": 0.50,
    "danger": 0.90,
}

URL_GENERIC_TEMPLATE_IDS = {
    "wordpress-detect",
    "wordpress-passive-detection",
}


def _normalize_text(value) -> str:
    return str(value or "").strip().lower()


def _is_wordpress_family(template) -> bool:
    template_id = _normalize_text(getattr(template, "template_id", ""))
    template_path = _normalize_text((getattr(template, "meta", {}) or {}).get("template_path"))
    tags = {_normalize_text(t) for t in (getattr(getattr(template, "info", None), "tags", None) or [])}
    return (
        "wordpress" in template_id
        or "wordpress" in tags
        or "wp" in tags
        or "/wordpress/" in template_path
    )


def _has_wordpress_fact(B) -> bool:
    for fact in B.get_by_type("tech"):
        if _normalize_text(getattr(fact, "value", "")) == "wordpress":
            return True
    return False


def _condition_score(conditions, B) -> float:
    if not conditions:
        return 0.0

    total_weight = 0.0
    weighted = 0.0
    for cond in conditions:
        best = 0.0
        for fact in B.get_by_type(getattr(cond, "type", None)):
            best = max(best, match_operator(cond, fact))
        weight = float(getattr(cond, "weight", 1.0) or 1.0)
        total_weight += weight
        weighted += best * weight

    if total_weight <= 0.0:
        return 0.0
    return weighted / total_weight


def compute_relevance(template, B, trigger_fact=None) -> float:
    """Estimate contextual relevance for the current fact set."""

    preconditions = getattr(template, "preconditions", None) or []
    if preconditions:
        return _condition_score(preconditions, B)

    conditions = getattr(getattr(template, "sieves", None), "conditions", None) or []
    if conditions:
        return _condition_score(conditions, B)

    template_id = _normalize_text(getattr(template, "template_id", ""))

    if trigger_fact is not None:
        trigger_type = _normalize_text(getattr(trigger_fact, "type", ""))
        trigger_value = _normalize_text(getattr(trigger_fact, "value", ""))

        if trigger_type == "url":
            if template_id in URL_GENERIC_TEMPLATE_IDS:
                return 0.95
            if _is_wordpress_family(template):
                return 0.12
            return 0.05

        if trigger_type == "tech" and trigger_value == "wordpress" and _is_wordpress_family(template):
            return 0.85

    if _is_wordpress_family(template) and _has_wordpress_fact(B):
        return 0.80

    if getattr(template, "outputs", None):
        return 0.15

    return 0.05


def compute_confidence(template, B) -> float:
    """Estimate confidence of running a template, based on available facts."""

    confidences = []

    inputs = getattr(getattr(template, "sieves", None), "inputs", None) or []
    for input_type in inputs:
        facts = B.get_by_type(input_type)
        if not facts:
            return 0.0
        confidences.append(max(f.confidence for f in facts))

    conditions = getattr(getattr(template, "sieves", None), "conditions", None) or []
    for cond in conditions:
        facts = B.get_by_type(cond.type)
        if facts:
            confidences.append(max(f.confidence for f in facts))

    if not confidences:
        return 0.5

    return sum(confidences) / len(confidences)


def compute_novelty(template, B) -> float:

    outputs = getattr(template, "outputs", []) or []
    if not outputs:
        return 0.0
    new_count = 0
    for out_type in outputs:
        if not B.has_type(out_type):
            new_count += 1
    return new_count / len(outputs)

def compute_score(
    template,
    B,
    index=None,
    all_templates=None,
    current_depth=None,
    historical_stats=None,
    trigger_fact=None,
) -> float:
    # Backward-compatible: orchestrator/matching_engine vẫn gọi được
    breakdown = compute_score_breakdown(
        template, B, index, all_templates, current_depth, historical_stats, trigger_fact
    )
    return breakdown.final_score

def compute_score_breakdown(
    template,
    B,
    index=None,
    all_templates=None,
    current_depth=None,
    historical_stats=None,
    trigger_fact=None,
) -> ScoringBreakdown:
    relevance = compute_relevance(template, B, trigger_fact)
    impact = compute_impact(template, B)
    novelty = compute_novelty(template, B)
    confidence = compute_confidence(template, B)
    chain_value = compute_chain_value(template, index, all_templates, B)
    cost = compute_cost_penalty(template)
    risk = compute_risk_penalty(template)
    depth_penalty = compute_depth_penalty(template, B, current_depth)
    hist_bonus = compute_historical_bonus(template, historical_stats)

    # Adaptive weights (có thể tune sau)
    score = (
        0.35 * relevance
        + 0.20 * impact
        + 0.15 * novelty
        + 0.15 * confidence
        + 0.20 * chain_value
        + hist_bonus
        - 0.10 * cost
        - 0.05 * risk
        - 0.05 * depth_penalty
    )

    logger.info(
        f"[SCORE]{getattr(template, 'template_id', '')} "
        f"relevance={relevance:.2f} impact={impact:.2f} novelty={novelty:.2f} "
        f"confidence={confidence:.2f} chain={chain_value:.2f} cost={cost:.2f} "
        f"risk={risk:.2f} depth_penalty={depth_penalty:.2f} hist={hist_bonus:.2f} final={score:.4f}"
    )

    return ScoringBreakdown(
        relevance=relevance,
        impact=impact,
        novelty=novelty,
        confidence=confidence,
        chain_value=chain_value,
        cost=cost,
        risk=risk,
        depth_penalty=depth_penalty,
        final_score=score,
    )


def is_vetoed(template, B, policy) -> bool:
    """Hard veto rules before considering a template."""

    risk = RISK.get(str(getattr(getattr(template, "execution", None), "risk", "medium")).lower(), 0.5)
    confidence = compute_confidence(template, B)

    if risk > getattr(policy, "risk_threshold", 0.6):
        return True

    if confidence < getattr(policy, "min_confidence", 0.3):
        return True

    max_depth = 0
    for cond in (getattr(getattr(template, "sieves", None), "conditions", None) or []):
        for fact in B.get_by_type(cond.type):
            max_depth = max(max_depth, fact.discovery_depth)

    if max_depth >= getattr(policy, "max_depth", 4):
        return True

    return False


def compute_final_score(template, B, policy, index=None, all_templates=None, trigger_fact=None) -> float:
    if is_vetoed(template, B, policy):
        return float("-inf")

    return compute_score(template, B, index, all_templates, trigger_fact=trigger_fact)
