"""ASMO entrypoint: run ASMO against a small subset of real Nuclei templates.

This file follows the spec in the prompt:
- uses ./nuclei-small (10-20 templates) instead of full nuclei-templates
- auto-generates signatures.json from YAML if needed
- loads nested signature schema and runs the orchestrator
"""

from __future__ import annotations

import argparse
from pathlib import Path

from models import Policy
from orchestrator import ASMOOrchestrator
from nuclei_runner import NucleiRunner
from signature_converter import convert_templates_to_signatures, load_signatures_from_json


def _build_arg_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description="Run ASMO with a small subset of Nuclei templates")
    ap.add_argument("--target", default="http://example.com", help="Scan target URL")
    ap.add_argument("--signatures", default="signatures.json", help="Path to signatures.json")
    ap.add_argument("--templates-dir", default="./nuclei-small", help="Directory with small subset of YAML templates")
    ap.add_argument(
        "--nuclei-bin",
        default=r"D:\Nuclei\nuclei_3.7.1_windows_amd64\nuclei.exe",
        help="Path to nuclei.exe",
    )
    ap.add_argument("--beam-width", type=int, default=3, help="Max templates per iteration")
    ap.add_argument("--max-iterations", type=int, default=5, help="Max ASMO iterations")
    ap.add_argument("--timeout", type=int, default=60, help="Nuclei per-template timeout (seconds)")
    ap.add_argument("--demo-mode", action="store_true", help="Enable controlled fallback facts for stable local demos")
    ap.add_argument("--export-graph-json", default="outputs/attack_graph.json", help="Path to export attack graph JSON")
    ap.add_argument("--export-graph-dot", default="outputs/attack_graph.dot", help="Path to export attack graph DOT")
    return ap


if __name__ == "__main__":
    args = _build_arg_parser().parse_args()

    target = args.target
    templates_dir = args.templates_dir
    signatures_path = args.signatures
    nuclei_bin = args.nuclei_bin

    templates_root = Path(templates_dir)
    yaml_count = len(list(templates_root.rglob("*.yaml"))) + len(list(templates_root.rglob("*.yml")))
    if not templates_root.exists() or yaml_count == 0:
        print("No YAML templates found. Please copy 10-20 templates into nuclei-small.")
        raise SystemExit(1)

    sig_path = Path(signatures_path)
    if (not sig_path.exists()) or sig_path.stat().st_size == 0:
        convert_templates_to_signatures(templates_dir, signatures_path)

    templates = load_signatures_from_json(signatures_path)
    if not templates:
        print("No signatures loaded. Cannot run ASMO.")
        raise SystemExit(1)
    policy = Policy.normal()
    policy.beam_width = int(args.beam_width)
    policy.max_iterations = int(args.max_iterations)

    runner = NucleiRunner(
        nuclei_bin=nuclei_bin,
        timeout=int(args.timeout),
        verbose=True,
        demo_mode=bool(args.demo_mode),
    )

    orchestrator = ASMOOrchestrator(
        templates=templates,
        policy=policy,
        runner=runner,
        demo_mode=bool(args.demo_mode),
    )

    B = orchestrator.run(target)

    export_json_path = Path(args.export_graph_json)
    export_dot_path = Path(args.export_graph_dot)
    export_json_path.parent.mkdir(parents=True, exist_ok=True)
    export_dot_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        orchestrator.attack_graph.export_json(str(export_json_path))
        print(f"[GRAPH-EXPORT] JSON saved to {export_json_path}")
    except Exception as exc:
        print(f"[GRAPH-EXPORT][WARN] JSON export failed: {exc}")

    try:
        orchestrator.attack_graph.export_dot(str(export_dot_path))
        print(f"[GRAPH-EXPORT] DOT saved to {export_dot_path}")
    except Exception as exc:
        print(f"[GRAPH-EXPORT][WARN] DOT export failed: {exc}")

    print("\n=== Final Blackboard ===")
    for fact in sorted(B.all_facts(), key=lambda f: (f.discovery_depth, f.type, str(f.value))):
        print(f"{fact.type}:{fact.value} confidence={fact.confidence} depth={fact.discovery_depth}")
