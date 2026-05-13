
from collections import deque
from models import Fact
from blackboard import Blackboard
from priority_queue import TemplatePriorityQueue
from matching_engine import MatchingEngine
from attack_graph import AttackGraph
import hashlib
import time
try:
    from policy_engine import PolicyEngine, NullPolicyEngine
except ImportError:
    PolicyEngine = None
    class NullPolicyEngine:
        def check_policy(self, template, blackboard, context=None):
            class Dummy:
                allowed = True
                reason = "policy engine disabled"
                policy_name = "null"
            return Dummy()


def make_fact_id(fact_type, value):
    raw = f"{fact_type}:{value}:{time.time()}".encode("utf-8")
    return "f_" + hashlib.sha1(raw).hexdigest()[:10]



class ASMOOrchestrator:
    def __init__(self, templates, policy, runner, policy_engine=None, demo_mode: bool = False):
        self.B = Blackboard()
        self.Q = deque()
        self.PQ = TemplatePriorityQueue()
        self.engine = MatchingEngine(templates, policy)
        self.policy = policy
        self.runner = runner
        self.demo_mode = bool(demo_mode)
        self.iteration = 0
        self.attack_graph = AttackGraph()
        # PolicyEngine integration (backward-compatible)
        if policy_engine is not None:
            self.policy_engine = policy_engine
        else:
            self.policy_engine = NullPolicyEngine()

    def add_fact(self, fact):
        changed = self.B.add_if_new_or_better(fact)
        if changed:
            self.Q.append(fact)
        return changed

    def initialize(self, target):
        url_fact = Fact(
            id=make_fact_id("url", target),
            type="url",
            value=target,
            confidence=1.0,
            target=target,
            discovery_depth=0,
            ttl=3,
            source={"tool": "user-input"},
            tags=[],
            metadata={},
        )

        protocol_value = "https" if str(target).startswith("https") else "http"
        protocol_fact = Fact(
            id=make_fact_id("protocol", protocol_value),
            type="protocol",
            value=protocol_value,
            confidence=1.0,
            target=target,
            discovery_depth=0,
            ttl=3,
            source={"tool": "inference"},
            tags=[],
            metadata={},
        )

        self.add_fact(url_fact)
        self.add_fact(protocol_fact)

        self.attack_graph.add_fact_node(url_fact)
        self.attack_graph.add_fact_node(protocol_fact)

    def _collect_trigger_facts(self, template):
        types = []
        try:
            types.extend(list(getattr(getattr(template, "sieves", None), "inputs", None) or []))
            for c in (getattr(getattr(template, "sieves", None), "conditions", None) or []):
                t = getattr(c, "type", None)
                if t:
                    types.append(t)
        except Exception:
            types = []

        trigger = []
        seen = set()
        for t in types:
            for fact in self.B.get_by_type(t):
                k = fact.key()
                if k in seen:
                    continue
                seen.add(k)
                trigger.append(fact)
        return trigger

    def sieve_new_facts(self):
        while self.Q:
            fact = self.Q.popleft()

            if fact.discovery_depth >= self.policy.max_depth:
                continue

            matches = self.engine.match_from_fact(fact, self.B)

            for template, score in matches:
                # Policy check before enqueue
                context = {
                    "current_depth": getattr(fact, "discovery_depth", 0),
                    "beam_width": getattr(self.policy, "beam_width", 3),
                    "target": getattr(fact, "target", None),
                    "risk_threshold": getattr(self.policy, "risk_threshold", 0.6),
                    "allow_exploit": getattr(self.policy, "allow_exploit", False),
                    "allow_bruteforce": getattr(self.policy, "allow_bruteforce", False),
                    "parallelism": getattr(self.policy, "beam_width", 3),
                }
                decision = self.policy_engine.check_policy(template, self.B, context)
                if not getattr(decision, "allowed", True):
                    print(f"[POLICY-VETO] {template.template_id}: {getattr(decision, 'reason', '')}")
                    continue
                print(f"[POLICY-ALLOW] {template.template_id}: {getattr(decision, 'reason', '')}")
                self.PQ.push_or_update(template, score)

    def execute_batch(self):
        batch = []

        while len(batch) < self.policy.beam_width and not self.PQ.empty():
            template, score = self.PQ.pop_best()
            if template is None:
                break
            batch.append((template, score))

        for template, score in batch:
            # Policy check again before execute (defensive, in case queue modified externally)
            context = {
                "beam_width": getattr(self.policy, "beam_width", 3),
                "risk_threshold": getattr(self.policy, "risk_threshold", 0.6),
                "allow_exploit": getattr(self.policy, "allow_exploit", False),
                "allow_bruteforce": getattr(self.policy, "allow_bruteforce", False),
                "parallelism": getattr(self.policy, "beam_width", 3),
            }
            decision = self.policy_engine.check_policy(template, self.B, context)
            if not getattr(decision, "allowed", True):
                print(f"[POLICY-VETO] {template.template_id}: {getattr(decision, 'reason', '')}")
                continue
            print(f"[EXEC] {template.template_id} policy=allowed score={score:.4f}")

            # Mark as executed to avoid infinite retry loops if the runner fails.
            self.engine.mark_executed(template, self.B)

            trigger_facts = self._collect_trigger_facts(template)

            try:
                new_facts = self.runner.run(template, self.B, context={"demo_mode": self.demo_mode})
            except Exception as exc:
                print(f"[ERROR] runner failed for {template.template_id}: {exc}")
                continue

            # Record execution even if no facts are produced
            try:
                self.attack_graph.add_execution(
                    trigger_facts,
                    template,
                    new_facts,
                    template_score=score,
                    policy_result="allowed",
                    status="executed",
                )
            except Exception:
                pass

            for fact in new_facts:
                self.add_fact(fact)

        return batch

    def run(self, target: str) -> Blackboard:
        self.initialize(target)

        for i in range(1, self.policy.max_iterations + 1):
            self.iteration = i
            print(f"\n[ITERATION {i}]")

            self.sieve_new_facts()

            if self.PQ.empty():
                break

            batch = self.execute_batch()
            if not batch:
                break

        return self.B