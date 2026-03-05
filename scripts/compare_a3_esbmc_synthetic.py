#!/usr/bin/env python3.11
"""
Compare A3 vs ESBMC on the synthetic Python suite using ground-truth labels.

Runs both analyzers on each file listed in GROUND_TRUTH_MANIFEST.json and
produces overall + per-bug-type metrics for BUG/SAFE classification.
"""

from __future__ import annotations

import argparse
import json
import os
import site
import subprocess
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Dict, List, Tuple

@dataclass
class ClassificationMetrics:
    tp: int = 0
    tn: int = 0
    fp: int = 0
    fn: int = 0
    unknown: int = 0
    total: int = 0

    def update(self, expected: str, predicted: str) -> None:
        self.total += 1
        if predicted == "UNKNOWN":
            self.unknown += 1
            return

        if expected == "BUG" and predicted == "BUG":
            self.tp += 1
        elif expected == "SAFE" and predicted == "SAFE":
            self.tn += 1
        elif expected == "SAFE" and predicted == "BUG":
            self.fp += 1
        elif expected == "BUG" and predicted == "SAFE":
            self.fn += 1

    def rates(self) -> Dict[str, float]:
        precision = self.tp / (self.tp + self.fp) if (self.tp + self.fp) else 0.0
        recall = self.tp / (self.tp + self.fn) if (self.tp + self.fn) else 0.0
        f1 = (
            2 * precision * recall / (precision + recall)
            if (precision + recall)
            else 0.0
        )
        accuracy = (self.tp + self.tn) / self.total if self.total else 0.0
        return {
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "accuracy": accuracy,
        }

    def to_dict(self) -> Dict:
        out = asdict(self)
        out.update(self.rates())
        return out


def load_manifest(manifest_path: Path) -> Dict:
    with open(manifest_path, "r") as f:
        return json.load(f)


def build_cases(manifest: Dict, suite_root: Path) -> List[Tuple[str, Path, str]]:
    cases: List[Tuple[str, Path, str]] = []
    for bug_type, files in manifest["bug_types"].items():
        for filename, info in files.items():
            expected = info["expected"]
            file_path = suite_root / bug_type / filename
            cases.append((bug_type, file_path, expected))
    return sorted(cases, key=lambda x: (x[0], x[1].name))


def run_a3(python_bin: str, file_path: Path, timeout_s: int) -> Tuple[str, str, float]:
    start = time.perf_counter()
    snippet = (
        "from pathlib import Path; "
        "from a3_python.analyzer import Analyzer; "
        "import json,sys; "
        "p=Path(sys.argv[1]); "
        "r=Analyzer(verbose=False, enable_interprocedural=True).analyze_file(p); "
        "v=getattr(r,'verdict',None); "
        "bi=getattr(r,'bug_instances',None); "
        "v=v if v in {'BUG','SAFE'} else ('BUG' if bi is not None and len(bi)>0 else ('SAFE' if bi is not None else 'UNKNOWN')); "
        "print(json.dumps({'verdict': v, 'bug_type': (getattr(r,'bug_type','') or '')}))"
    )
    cmd = [python_bin, "-c", snippet, str(file_path)]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_s)
        if proc.returncode != 0:
            return "UNKNOWN", f"A3_SUBPROCESS_RC:{proc.returncode}", time.perf_counter() - start
        lines = [ln.strip() for ln in (proc.stdout or "").splitlines() if ln.strip()]
        payload = json.loads(lines[-1]) if lines else {"verdict": "UNKNOWN", "bug_type": ""}
        verdict = payload.get("verdict", "UNKNOWN")
        if verdict not in {"BUG", "SAFE"}:
            verdict = "UNKNOWN"
        return verdict, payload.get("bug_type", ""), time.perf_counter() - start
    except subprocess.TimeoutExpired:
        return "UNKNOWN", "A3_TIMEOUT", time.perf_counter() - start
    except Exception as exc:
        return "UNKNOWN", f"A3_ERROR:{exc}", time.perf_counter() - start


def run_esbmc(esbmc_bin: Path, python_bin: str, file_path: Path, timeout_s: int) -> Tuple[str, str, float, int]:
    start = time.perf_counter()
    env = os.environ.copy()
    env["PYTHONPATH"] = site.getusersitepackages()

    cmd = [
        str(esbmc_bin),
        str(file_path),
        "--python",
        python_bin,
        "--quiet",
        "--result-only",
    ]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_s,
            env=env,
        )
        output = (proc.stdout or "") + "\n" + (proc.stderr or "")
        if "VERIFICATION FAILED" in output:
            verdict = "BUG"
        elif "VERIFICATION SUCCESSFUL" in output:
            verdict = "SAFE"
        else:
            verdict = "UNKNOWN"
        return verdict, output[-2000:], time.perf_counter() - start, proc.returncode
    except subprocess.TimeoutExpired:
        return "UNKNOWN", "TIMEOUT", time.perf_counter() - start, 124


def main() -> None:
    parser = argparse.ArgumentParser(description="Compare A3 vs ESBMC synthetic-suite performance")
    parser.add_argument("--suite", type=Path, default=Path("tests/synthetic_suite"))
    parser.add_argument("--manifest", type=Path, default=Path("tests/synthetic_suite/GROUND_TRUTH_MANIFEST.json"))
    parser.add_argument("--esbmc", type=Path, default=Path("external_tools/esbmc/build/src/esbmc/esbmc"))
    parser.add_argument("--python", dest="python_bin", default="python3.11")
    parser.add_argument("--a3-timeout", type=int, default=45)
    parser.add_argument("--esbmc-timeout", type=int, default=60)
    parser.add_argument("--start", type=int, default=0, help="Start index into sorted case list")
    parser.add_argument("--limit", type=int, default=0, help="Only run N cases from start index (0 = all remaining)")
    parser.add_argument("--output", type=Path, default=Path("results/synthetic_comparison_python311.json"))
    args = parser.parse_args()

    manifest = load_manifest(args.manifest)
    cases = build_cases(manifest, args.suite)
    if args.start and args.start > 0:
        cases = cases[args.start:]
    if args.limit and args.limit > 0:
        cases = cases[:args.limit]

    tools = ["a3", "esbmc"]
    overall: Dict[str, ClassificationMetrics] = {t: ClassificationMetrics() for t in tools}
    by_bug_type: Dict[str, Dict[str, ClassificationMetrics]] = {}
    details: List[Dict] = []

    for idx, (bug_type, file_path, expected) in enumerate(cases, 1):
        if bug_type not in by_bug_type:
            by_bug_type[bug_type] = {t: ClassificationMetrics() for t in tools}

        a3_verdict, a3_bug_type, a3_sec = run_a3(args.python_bin, file_path, args.a3_timeout)
        esbmc_verdict, esbmc_note, esbmc_sec, esbmc_rc = run_esbmc(
            args.esbmc,
            args.python_bin,
            file_path,
            args.esbmc_timeout,
        )

        overall["a3"].update(expected, a3_verdict)
        overall["esbmc"].update(expected, esbmc_verdict)
        by_bug_type[bug_type]["a3"].update(expected, a3_verdict)
        by_bug_type[bug_type]["esbmc"].update(expected, esbmc_verdict)

        details.append(
            {
                "bug_type": bug_type,
                "file": str(file_path),
                "expected": expected,
                "a3": {
                    "verdict": a3_verdict,
                    "bug_type": a3_bug_type,
                    "runtime_sec": round(a3_sec, 4),
                },
                "esbmc": {
                    "verdict": esbmc_verdict,
                    "return_code": esbmc_rc,
                    "runtime_sec": round(esbmc_sec, 4),
                    "note": esbmc_note,
                },
            }
        )

        if idx % 20 == 0:
            print(f"[{idx}/{len(cases)}] processed")

    output = {
        "metadata": {
            "total_cases": len(cases),
            "suite": str(args.suite),
            "manifest": str(args.manifest),
            "esbmc": str(args.esbmc),
            "python": args.python_bin,
            "a3_timeout_sec": args.a3_timeout,
            "esbmc_timeout_sec": args.esbmc_timeout,
        },
        "overall": {tool: overall[tool].to_dict() for tool in tools},
        "by_bug_type": {
            b: {tool: metrics[tool].to_dict() for tool in tools}
            for b, metrics in by_bug_type.items()
        },
        "details": details,
    }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, "w") as f:
        json.dump(output, f, indent=2)

    print(f"Saved comparison: {args.output}")
    print("Overall:")
    for tool in tools:
        m = output["overall"][tool]
        print(
            f"  {tool.upper():<6} total={m['total']} tp={m['tp']} tn={m['tn']} fp={m['fp']} fn={m['fn']} unknown={m['unknown']} "
            f"precision={m['precision']:.3f} recall={m['recall']:.3f} f1={m['f1']:.3f} accuracy={m['accuracy']:.3f}"
        )


if __name__ == "__main__":
    main()
