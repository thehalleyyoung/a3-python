"""
SARIF 2.1.0 serializer for A³ results.

Converts the internal results dict (from _analyze_project) to the
SARIF JSON format consumed by GitHub Code Scanning, VS Code SARIF Viewer,
and other SARIF-compatible tools.

Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from a3_python import __version__

# ── Bug-type metadata ────────────────────────────────────────────────────────

_BUG_RULES: dict[str, dict[str, str]] = {
    "DIV_ZERO": {
        "id": "PFS001",
        "name": "DivisionByZero",
        "shortDescription": "Potential division by zero",
        "fullDescription": (
            "An arithmetic division or modulo operation may receive a zero "
            "divisor, causing a ZeroDivisionError at runtime."
        ),
        "level": "error",
        "precision": "high",
        "cwe": "CWE-369",
    },
    "NULL_PTR": {
        "id": "PFS002",
        "name": "NoneReference",
        "shortDescription": "Potential NoneType dereference",
        "fullDescription": (
            "An attribute access, subscript, or call may be performed on a "
            "value that could be None, causing an AttributeError or TypeError."
        ),
        "level": "error",
        "precision": "high",
        "cwe": "CWE-476",
    },
    "INDEX_OOB": {
        "id": "PFS003",
        "name": "IndexOutOfBounds",
        "shortDescription": "Potential index out of bounds",
        "fullDescription": (
            "A list/tuple subscript may use an index that is outside the "
            "valid range, causing an IndexError."
        ),
        "level": "error",
        "precision": "high",
        "cwe": "CWE-129",
    },
    "KEY_ERROR": {
        "id": "PFS004",
        "name": "KeyError",
        "shortDescription": "Potential missing dictionary key",
        "fullDescription": (
            "A dictionary subscript may use a key that does not exist, "
            "causing a KeyError."
        ),
        "level": "warning",
        "precision": "medium",
        "cwe": "CWE-754",
    },
    "TYPE_ERROR": {
        "id": "PFS005",
        "name": "TypeError",
        "shortDescription": "Potential type error in operation",
        "fullDescription": (
            "An operation may receive operands of incompatible types, "
            "causing a TypeError at runtime."
        ),
        "level": "error",
        "precision": "medium",
        "cwe": "CWE-843",
    },
    "OVERFLOW": {
        "id": "PFS006",
        "name": "IntegerOverflow",
        "shortDescription": "Potential integer overflow",
        "fullDescription": (
            "An arithmetic operation may overflow the expected integer range. "
            "While Python ints have arbitrary precision, this may cause "
            "performance issues or logic errors."
        ),
        "level": "warning",
        "precision": "low",
        "cwe": "CWE-190",
    },
    "ASSERT_FAIL": {
        "id": "PFS007",
        "name": "AssertionFailure",
        "shortDescription": "Potential assertion failure",
        "fullDescription": (
            "An assert statement may fail at runtime, indicating a violated "
            "invariant or precondition."
        ),
        "level": "warning",
        "precision": "medium",
        "cwe": "CWE-617",
    },
    "UNBOUND_VAR": {
        "id": "PFS008",
        "name": "UnboundVariable",
        "shortDescription": "Potential unbound local variable",
        "fullDescription": (
            "A local variable may be referenced before assignment on some "
            "execution paths, causing an UnboundLocalError."
        ),
        "level": "error",
        "precision": "high",
        "cwe": "CWE-457",
    },
    "SSRF": {
        "id": "PFS009",
        "name": "ServerSideRequestForgery",
        "shortDescription": "Potential SSRF vulnerability",
        "fullDescription": (
            "User-controlled input may flow to a URL in an HTTP request, "
            "allowing server-side request forgery."
        ),
        "level": "error",
        "precision": "medium",
        "cwe": "CWE-918",
    },
    "SQL_INJECTION": {
        "id": "PFS010",
        "name": "SQLInjection",
        "shortDescription": "Potential SQL injection",
        "fullDescription": (
            "User-controlled input may be interpolated into a SQL query "
            "without proper sanitisation."
        ),
        "level": "error",
        "precision": "medium",
        "cwe": "CWE-89",
    },
    "CMD_INJECTION": {
        "id": "PFS011",
        "name": "CommandInjection",
        "shortDescription": "Potential command injection",
        "fullDescription": (
            "User-controlled input may flow to a shell command, allowing "
            "arbitrary command execution."
        ),
        "level": "error",
        "precision": "medium",
        "cwe": "CWE-78",
    },
    "PATH_TRAVERSAL": {
        "id": "PFS012",
        "name": "PathTraversal",
        "shortDescription": "Potential path traversal",
        "fullDescription": (
            "User-controlled input may be used in a file path without "
            "proper sanitisation, allowing access to unintended files."
        ),
        "level": "error",
        "precision": "medium",
        "cwe": "CWE-22",
    },
    "WEAK_CRYPTO": {
        "id": "PFS013",
        "name": "WeakCryptography",
        "shortDescription": "Use of weak cryptographic algorithm",
        "fullDescription": (
            "A cryptographic operation uses a weak or deprecated algorithm "
            "(e.g. MD5, SHA1 for security purposes)."
        ),
        "level": "warning",
        "precision": "high",
        "cwe": "CWE-327",
    },
}

# Fallback for unknown bug types
_DEFAULT_RULE = {
    "id": "PFS999",
    "name": "UnclassifiedBug",
    "shortDescription": "Potential runtime error",
    "fullDescription": "A potential runtime error was detected by static analysis.",
    "level": "warning",
    "precision": "medium",
    "cwe": "CWE-710",
}


def _rule_for(bug_type: str) -> dict[str, str]:
    """Get the SARIF rule descriptor for a bug type."""
    return _BUG_RULES.get(bug_type, {**_DEFAULT_RULE, "name": bug_type})


def _make_rule_id(bug_type: str) -> str:
    rule = _rule_for(bug_type)
    return rule["id"]


# ── Public API ────────────────────────────────────────────────────────────────


def results_to_sarif(
    results: dict[str, Any],
    repo_root: Path | str,
) -> dict[str, Any]:
    """
    Convert a a3 results dict to SARIF 2.1.0 JSON.

    Parameters
    ----------
    results : dict
        The results dict produced by ``_analyze_project`` and saved via
        ``--save-results``.  Expected keys: ``prod_bugs``, ``dse_reachable``,
        ``project``, ``total_functions``, ``total_bugs``, ``grand_fp``.
        May also include ``_call_graph`` and ``_summaries`` for rich location data.
    repo_root : Path
        Absolute path to the repository root.  File paths in the SARIF output
        will be made relative to this.

    Returns
    -------
    dict
        A SARIF 2.1.0 JSON-serialisable dict.
    """
    repo_root = Path(repo_root).resolve()

    # Extract rich data if available (in-memory only, not serialised)
    call_graph = results.get("_call_graph")
    summaries = results.get("_summaries", {})
    dse_full = results.get("dse_reachable_full", {})

    # Build a lookup: func_name -> FunctionInfo (file_path, line_number)
    func_info_map: dict[str, Any] = {}
    if call_graph:
        for fname, finfo in call_graph.functions.items():
            func_info_map[fname] = finfo

    # Build a lookup: func_name -> bug line numbers from crash summaries
    # crash_summaries store BytecodeLocation with line_number per bug
    bug_lines_map: dict[str, dict[str, int | None]] = {}
    if summaries:
        for fname, summary in summaries.items():
            analyzer_crash_locs = getattr(summary, "_crash_locations", None)
            # crash_locations aren't on the summary; instead look at bytecode_instructions
            # to find the bug line from the code object
            if fname not in bug_lines_map:
                bug_lines_map[fname] = {}

    # Collect all unique bug types to build the rules array
    all_bug_types: set[str] = set()
    for _, bug_type in results.get("prod_bugs", []):
        all_bug_types.add(bug_type)
    for func_name, (status, bug_type) in results.get("dse_reachable", {}).items():
        all_bug_types.add(bug_type)

    # Build rules array (one per unique bug type)
    rules = []
    rule_index_map: dict[str, int] = {}
    for i, bug_type in enumerate(sorted(all_bug_types)):
        meta = _rule_for(bug_type)
        rule_index_map[bug_type] = i
        rules.append({
            "id": meta["id"],
            "name": meta["name"],
            "shortDescription": {"text": meta["shortDescription"]},
            "fullDescription": {"text": meta["fullDescription"]},
            "defaultConfiguration": {"level": meta["level"]},
            "properties": {
                "precision": meta["precision"],
                "tags": ["security" if "CWE-" in meta.get("cwe", "") and int(meta["cwe"].split("-")[1]) < 400 else "correctness"],
            },
            "helpUri": f"https://cwe.mitre.org/data/definitions/{meta['cwe'].split('-')[1]}.html",
        })

    # Build results array
    sarif_results = []

    # DSE-confirmed reachable bugs (highest confidence)
    dse_confirmed: set[str] = set()
    for func_name, (status, bug_type) in results.get("dse_reachable", {}).items():
        dse_confirmed.add(func_name)
        cex = dse_full.get(func_name, (None, None, None))[2] if dse_full else None
        sarif_results.append(
            _make_result(
                func_name, bug_type, rule_index_map, repo_root,
                dse_confirmed=True,
                func_info_map=func_info_map,
                counterexample=cex,
            )
        )

    # Production candidates not already covered by DSE
    for func_name, bug_type in results.get("prod_bugs", []):
        if func_name not in dse_confirmed:
            sarif_results.append(
                _make_result(
                    func_name, bug_type, rule_index_map, repo_root,
                    dse_confirmed=False,
                    func_info_map=func_info_map,
                )
            )

    # Assemble SARIF envelope
    sarif: dict[str, Any] = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "a3",
                        "semanticVersion": __version__,
                        "informationUri": "https://github.com/thehalleyyoung/A³",
                        "rules": rules,
                    }
                },
                "results": sarif_results,
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "toolExecutionNotifications": [],
                    }
                ],
                "properties": {
                    "metrics": {
                        "totalFunctions": results.get("total_functions", 0),
                        "totalBugs": results.get("total_bugs", 0),
                        "provenFP": results.get("grand_fp", 0),
                        "remainingCandidates": results.get("remaining_count", 0),
                    }
                },
            }
        ],
    }
    return sarif


def write_sarif(sarif: dict[str, Any], output_path: Path | str) -> None:
    """Write a SARIF dict to a JSON file."""
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(sarif, f, indent=2)


def load_sarif(path: Path | str) -> dict[str, Any]:
    """Load a SARIF JSON file."""
    with open(path) as f:
        return json.load(f)


# ── Internal helpers ─────────────────────────────────────────────────────────


def _parse_func_location(
    func_name: str,
    repo_root: Path,
    func_info_map: dict[str, Any] | None = None,
) -> tuple[str, int]:
    """
    Extract (relative_file_path, line_number) from a qualified function name.

    Uses the call graph's FunctionInfo when available for precise locations.
    Falls back to dotted-module → path heuristic otherwise.
    """
    # Try call-graph FunctionInfo first (has real file_path + line_number)
    if func_info_map:
        info = func_info_map.get(func_name)
        if info is not None:
            abs_path = Path(getattr(info, "file_path", ""))
            line = getattr(info, "line_number", 1) or 1
            try:
                rel = abs_path.resolve().relative_to(repo_root)
                return str(rel), line
            except ValueError:
                # file_path is already relative or not under repo_root
                return str(abs_path), line

    # Fallback: dotted module → file path
    parts = func_name.split(".")

    for depth in range(len(parts), 0, -1):
        candidate = Path(*parts[:depth]).with_suffix(".py")
        full = repo_root / candidate
        if full.exists():
            return str(candidate), 1

    module_parts = parts[:-1] if len(parts) > 1 else parts
    rel = Path(*module_parts).with_suffix(".py") if module_parts else Path(func_name + ".py")
    return str(rel), 1


def _read_source_snippet(
    rel_path: str,
    line: int,
    repo_root: Path,
    context_lines: int = 3,
) -> tuple[str | None, int, int]:
    """
    Read source code lines around the bug location.

    Returns (snippet_text, start_line, end_line) or (None, line, line).
    """
    abs_path = repo_root / rel_path
    if not abs_path.is_file():
        return None, line, line

    try:
        text = abs_path.read_text(encoding="utf-8", errors="replace")
        lines = text.splitlines()
        total = len(lines)
        start = max(0, line - 1 - context_lines)
        end = min(total, line + context_lines)
        snippet = "\n".join(lines[start:end])
        return snippet, start + 1, end
    except Exception:
        return None, line, line


def _make_result(
    func_name: str,
    bug_type: str,
    rule_index_map: dict[str, int],
    repo_root: Path,
    *,
    dse_confirmed: bool = False,
    func_info_map: dict[str, Any] | None = None,
    counterexample: Any = None,
) -> dict[str, Any]:
    """Build a single SARIF result object with rich location and code context."""
    meta = _rule_for(bug_type)
    rel_path, line = _parse_func_location(func_name, repo_root, func_info_map)

    # Extract the last component as the function display name
    display_name = func_name.rsplit(".", 1)[-1] if "." in func_name else func_name

    # Read source code snippet
    snippet_text, snippet_start, snippet_end = _read_source_snippet(
        rel_path, line, repo_root
    )

    # Build message with more context
    msg_parts = [f"{meta['shortDescription']} in `{display_name}()`"]
    if dse_confirmed:
        msg_parts.append("(DSE-confirmed reachable)")
    message_text = " ".join(msg_parts)

    # Build region with real line number
    region: dict[str, Any] = {
        "startLine": line,
    }
    if snippet_text:
        region["snippet"] = {"text": snippet_text}

    # Build physical location
    phys_loc: dict[str, Any] = {
        "artifactLocation": {
            "uri": rel_path,
            "uriBaseId": "%SRCROOT%",
        },
        "region": region,
    }

    # Build the result
    result: dict[str, Any] = {
        "ruleId": meta["id"],
        "ruleIndex": rule_index_map.get(bug_type, 0),
        "level": meta["level"],
        "message": {"text": message_text},
        "locations": [
            {
                "physicalLocation": phys_loc,
                "logicalLocations": [
                    {
                        "fullyQualifiedName": func_name,
                        "kind": "function",
                    }
                ],
            }
        ],
        "properties": {
            "dseConfirmed": dse_confirmed,
            "bugType": bug_type,
            "qualifiedName": func_name,
        },
    }

    # Add counterexample from DSE if available
    if counterexample and isinstance(counterexample, dict):
        cex_lines = []
        for param, value in counterexample.items():
            cex_lines.append(f"  {param} = {value!r}")
        if cex_lines:
            result["message"]["text"] += (
                "\n\nCounterexample (inputs that trigger the bug):\n"
                + "\n".join(cex_lines)
            )
            result["properties"]["counterexample"] = counterexample

    return result
