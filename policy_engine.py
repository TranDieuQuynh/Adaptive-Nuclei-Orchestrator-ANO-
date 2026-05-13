from models import PolicyDecision, TemplateSignature, Fact
import logging


def _setup_logger(name: str = "asmo.policy") -> logging.Logger:
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger
    logger.setLevel(logging.INFO)
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
    logger.addHandler(handler)
    return logger

logger = _setup_logger()

class NullPolicyEngine:
    """Default allow-all policy engine for backward compatibility."""
    def check_policy(self, template, blackboard, context=None):
        return PolicyDecision(allowed=True, reason="policy engine disabled", policy_name="null")

class PolicyEngine:
    def __init__(self, policy_config=None):
        self.policy_config = policy_config or {}

    def check_policy(self, template: TemplateSignature, blackboard, context=None) -> PolicyDecision:
        """
        Evaluate all policies, return first veto or allow.
        """
        for fn in [
            self.risk_policy,
            self.bruteforce_policy,
            self.exploit_policy,
            self.auth_policy,
            self.scope_policy,
            self.state_change_policy,
            self.depth_policy,
            self.rate_limit_policy,
        ]:
            decision = fn(template, blackboard, context)
            logger.info(f"[POLICY-CHECK]{template.template_id}:{fn.__name__}:{decision.reason}")
            if not decision.allowed:
                logger.info(f"[POLICY-VETO]{template.template_id}:{decision.reason}")
                return decision
        logger.info(f"[POLICY-ALLOW]{template.template_id}:safe passive template")
        return PolicyDecision(allowed=True, reason="safe passive template", policy_name="policy_engine")

    def risk_policy(self, template, blackboard, context=None):
        threshold = getattr(self.policy_config, "risk_threshold", 0.6)
        risk = getattr(template, "risk", 0.0)
        if risk and risk > threshold:
            return PolicyDecision(False, f"risk {risk} > threshold {threshold}", "risk_policy")
        return PolicyDecision(True, "risk within threshold", "risk_policy")

    def bruteforce_policy(self, template, blackboard, context=None):
        allow = getattr(self.policy_config, "allow_bruteforce", False)
        if "bruteforce" in (getattr(template, "side_effects", []) or []):
            if not allow:
                return PolicyDecision(False, "bruteforce disabled", "bruteforce_policy")
        return PolicyDecision(True, "bruteforce allowed", "bruteforce_policy")

    def exploit_policy(self, template, blackboard, context=None):
        allow = getattr(self.policy_config, "allow_exploit", False)
        if hasattr(template, "is_offensive") and template.is_offensive():
            if not allow:
                return PolicyDecision(False, "exploit disabled", "exploit_policy")
        return PolicyDecision(True, "exploit allowed", "exploit_policy")

    def auth_policy(self, template, blackboard, context=None):
        if getattr(template, "requires_auth", False):
            # Check if blackboard has credential/session/token
            for t in ["credential", "session", "token"]:
                if blackboard.has_type(t):
                    return PolicyDecision(True, "auth present", "auth_policy")
            return PolicyDecision(False, "auth required but missing", "auth_policy")
        return PolicyDecision(True, "no auth required", "auth_policy")

    def scope_policy(self, template, blackboard, context=None):
        # Placeholder: always allow, can extend for SSRF, forbidden port, etc.
        return PolicyDecision(True, "scope allowed", "scope_policy")

    def state_change_policy(self, template, blackboard, context=None):
        allow = getattr(self.policy_config, "allow_state_change", False)
        effects = getattr(template, "effects", []) or []
        if any(e in ["state_change", "delete", "upload", "mutation"] for e in effects):
            if not allow:
                return PolicyDecision(False, "state-changing action disabled", "state_change_policy")
        return PolicyDecision(True, "no state-changing effect or allowed", "state_change_policy")

    def depth_policy(self, template, blackboard, context=None):
        max_depth = getattr(self.policy_config, "max_depth", 4)
        # Lấy max discovery_depth của các input/condition fact
        max_fact_depth = 0
        for t in (getattr(getattr(template, "sieves", None), "inputs", None) or []):
            for f in blackboard.get_by_type(t):
                max_fact_depth = max(max_fact_depth, getattr(f, "discovery_depth", 0))
        for c in (getattr(getattr(template, "sieves", None), "conditions", None) or []):
            for f in blackboard.get_by_type(getattr(c, "type", None)):
                max_fact_depth = max(max_fact_depth, getattr(f, "discovery_depth", 0))
        if max_fact_depth > max_depth:
            return PolicyDecision(False, f"depth {max_fact_depth} > max_depth {max_depth}", "depth_policy")
        return PolicyDecision(True, "depth within limit", "depth_policy")

    def rate_limit_policy(self, template, blackboard, context=None):
        # Placeholder: always allow, can extend for request/parallel/timeout
        return PolicyDecision(True, "rate within limit", "rate_limit_policy")
