from __future__ import annotations

from dataclasses import dataclass, field
import time
from typing import Any, Dict, List, Optional, Union
from enum import Enum


@dataclass(frozen=True)
class Fact:
    id: str
    type: str
    value: Any
    confidence: float = 1.0
    source: Dict[str, Any] = field(default_factory=dict)
    target: Optional[str] = None
    discovery_depth: int = 0
    timestamp: float = field(default_factory=lambda: time.time())
    ttl: int = 3
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    provenance: List[str] = field(default_factory=list)  # Trace Fact -> Template -> Fact

    def key(self):
        normalized_value = str(self.value).lower()
        return (self.type, normalized_value, self.target)

    def id_(self) -> str:
        return self.id


@dataclass(frozen=True)
class Condition:
    type: str
    operator: str
    value: Any = None
    weight: float = 1.0
    pattern: Optional[str] = None


@dataclass(frozen=True)
class Scope:
    protocol: Optional[str] = None
    risk_level: str = "medium"
    allowed_ports: List[int] = field(default_factory=list)


@dataclass(frozen=True)
class SignatureInfo:
    name: str
    severity: str
    impact_score: float = 0.1
    tags: List[str] = field(default_factory=list)


@dataclass(frozen=True)
class ExecutionProfile:
    cost: str = "normal"
    risk: str = "medium"
    timeout: int = 30


@dataclass(frozen=True)
class OutputMapping:
    source_key: str
    to_fact_type: str
    confidence_boost: float = 0.0


@dataclass(frozen=True)
class SieveProfile:
    inputs: List[str] = field(default_factory=list)
    conditions: List[Condition] = field(default_factory=list)
    scope: Scope = field(default_factory=Scope)



@dataclass
class TemplateSignature:
    template_id: str
    info: SignatureInfo
    sieves: SieveProfile
    execution: ExecutionProfile
    outputs: List[str] = field(default_factory=list)
    effects: List[str] = field(default_factory=list)
    side_effects: List[str] = field(default_factory=list)
    preconditions: List[Condition] = field(default_factory=list)
    inputs: List[str] = field(default_factory=list)  # alias for sieves.inputs
    output_mapping: List[OutputMapping] = field(default_factory=list)
    meta: Dict[str, Any] = field(default_factory=dict)
    risk: float = 0.0
    cost: float = 0.0
    requires_auth: bool = False
    confidence_required: float = 0.0
    depth_limit: int = 0
    tags: List[str] = field(default_factory=list)
    template_path: str = ""
    severity: str = "info"

    def risk_score(self) -> float:
        # Backward-compatible: prefer execution.risk if available
        if hasattr(self, 'execution') and hasattr(self.execution, 'risk'):
            risk_map = {"safe": 0.1, "medium": 0.5, "danger": 0.9, "high": 1.0}
            return risk_map.get(str(self.execution.risk).lower(), 0.5)
        return self.risk

    def cost_score(self) -> float:
        if hasattr(self, 'execution') and hasattr(self.execution, 'cost'):
            cost_map = {"fast": 0.1, "normal": 0.4, "slow": 0.7, "expensive": 1.0}
            return cost_map.get(str(self.execution.cost).lower(), 0.4)
        return self.cost

    def is_offensive(self) -> bool:
        # Heuristic: if any effect/side_effect is exploit/fuzzing/state_change
        offensive_keywords = {"exploit", "fuzzing", "state_change", "bruteforce", "attack"}
        for e in (self.effects or []) + (self.side_effects or []):
            if any(k in str(e).lower() for k in offensive_keywords):
                return True
        return False
# --- PolicyConfig, ScoringBreakdown, MatchDecision, SieveDecision, PolicyDecision ---

@dataclass
class PolicyConfig:
    allow_bruteforce: bool = False
    allow_exploit: bool = False
    allow_authenticated: bool = False
    risk_threshold: float = 0.6
    max_depth: int = 4
    beam_width: int = 3
    max_iterations: int = 20

@dataclass
class ScoringBreakdown:
    relevance: float = 0.0
    impact: float = 0.0
    novelty: float = 0.0
    confidence: float = 0.0
    chain_value: float = 0.0
    cost: float = 0.0
    risk: float = 0.0
    depth_penalty: float = 0.0
    final_score: float = 0.0

@dataclass
class MatchDecision:
    matched: bool
    reason: str = ""
    score: float = 0.0
    breakdown: Optional[ScoringBreakdown] = None

@dataclass
class SieveDecision:
    accepted: bool
    reason: str = ""
    sieve_name: str = ""

@dataclass
class PolicyDecision:
    allowed: bool
    reason: str = ""
    policy_name: str = ""


@dataclass
class Policy:
    risk_threshold: float = 0.6
    min_confidence: float = 0.3
    max_depth: int = 4
    beam_width: int = 3
    max_iterations: int = 20

    @staticmethod
    def safe():
        return Policy(risk_threshold=0.3, min_confidence=0.5, max_depth=3, beam_width=2)

    @staticmethod
    def normal():
        return Policy(risk_threshold=0.6, min_confidence=0.3, max_depth=4, beam_width=3)

    @staticmethod
    def aggressive():
        return Policy(risk_threshold=0.9, min_confidence=0.2, max_depth=6, beam_width=5)
