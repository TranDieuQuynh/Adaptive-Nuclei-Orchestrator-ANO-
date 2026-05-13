Thesis demo flow (8 parts, runtime-driven)

Run command (one line):

powershell -ExecutionPolicy Bypass -File .\demo_runs\demo_thesis.ps1

What this demo is designed to show:

1) Initial target state (facts-first, not vuln-first)
- Reads seed facts from demo_runs/facts_seed_thesis.json.
- Shows target + initial facts (tech, endpoints, auth feature).

2) Signature/descriptor model
- Uses demo_runs/signatures_thesis_demo.yaml.
- Each template has: precondition, required_facts, required_vars, matching_features, output, cost/confidence.

3) Blackboard as orchestration core
- Engine starts from facts and continuously updates blackboard.
- Artifacts: facts_latest.json, facts_history.json.

4) Dynamic matching
- Query-based runtime selection (no static fixed workflow).
- Evidence printed from scheduling.template_query_history.

5) Fan-out
- Multiple templates can be selected from the same facts set.
- Evidence printed from scheduling.scheduler_decisions and depth summaries.

6) Multi-step dynamic chaining
- Output facts from previous templates trigger next templates.
- Script prints [Match] -> [Execute] -> [Output] sequences.

7) Loop/cost control
- Shows loop prevention events, depth execution counts, and stop reason.
- Repeated templates that already produced no novelty are strongly penalized and can be pruned.

8) Decision layer
- If idor is present, data-leak branch is boosted.
- If xss is present, exploit/impact branch is boosted.

9) Attack graph runtime output
- attack_graph.json is generated.
- Mermaid graph is generated at demo_runs/attack_graph_thesis.mmd.

10) Risk scoring
- facts_result.json contains risk_summary with risk_level (HIGH/MEDIUM/LOW) and risk_score.

Suggested presentation sequence (3-6 minutes):
1) Run the one-liner.
2) Pause at PHAN 1 and explain "state-first".
3) Pause at PHAN 5 and explain fan-out.
4) Pause at PHAN 6 and explain chaining.
5) End at PHAN 8 and open attack_graph.json + attack_graph_thesis.mmd.
6) Show risk scoring block (HIGH/MEDIUM/LOW).

Optional tuning:
- More branching: -MaxTemplatesPerDepth 8
- Deeper chain search: -MaxDepth 4
- More parallelism: -MaxParallelWorkers 4
