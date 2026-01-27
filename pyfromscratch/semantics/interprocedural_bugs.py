"""
Interprocedural Bug Tracker for All Bug Types.

Extends the interprocedural analysis to detect ALL bug types (not just security/taint)
across function and file boundaries. This is the unified bug detection layer.

Architecture:
1. **TaintSummary**: Tracks information flow (security bugs like SQL injection)
2. **CrashSummary**: Tracks crash conditions (NULL_PTR, BOUNDS, DIV_ZERO, etc.)
3. **InterproceduralBugTracker**: Combines both for complete analysis

Usage:
    tracker = InterproceduralBugTracker.from_project(Path("my_project"))
    bugs = tracker.find_all_bugs()
    
This produces a unified report of all potential bugs reachable from entry points.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional, Tuple, Any
from pathlib import Path
from enum import IntEnum

from ..confidence_interval import ReachabilityIntervalPTS, RiskInterval, ConcreteWitnessEvidence
from .crash_summaries import (
    REGISTERED_BUG_TYPES, PRECONDITION_TO_BUG,
    PreconditionType, Precondition,
    ExceptionType, EXCEPTION_TO_BUG,
    Nullability,
    CrashSummary, CrashSummaryComputer,
    BytecodeCrashSummaryComputer,  # Prefer bytecode-level analysis
    InterproceduralBugSummary, compute_all_bug_summaries,
)
from .summaries import TaintSummary, SummaryComputer
from .interprocedural_taint import InterproceduralContext
from .intraprocedural_taint import IntraproceduralTaintAnalyzer, IntraproceduralBug
from ..cfg.call_graph import CallGraph, CallSite, build_call_graph_from_directory
from ..frontend.entry_points import detect_entry_points_in_project, get_entry_point_functions
from ..confidence_scoring import ConfidenceScorer


# ============================================================================
# BUG REPORT
# ============================================================================

@dataclass
class InterproceduralBug:
    """
    A bug found through interprocedural analysis.
    
    Contains full provenance: the call chain from entry point to bug site.
    Uses string bug type names from pyfromscratch/unsafe/registry.py as the
    canonical source of truth (e.g., 'DIV_ZERO', 'NULL_PTR', 'SQL_INJECTION').
    
    The `inferred_source` field indicates whether sensitive data was identified through
    heuristic name-based inference (e.g., variable named 'password') rather than explicit
    source tracking. This should be set to True when the bug depends on sensitivity inference
    from `infer_sensitivity_from_name()` in security_tracker_lattice.py.
    """
    bug_type: str  # String name from REGISTERED_BUG_TYPES
    
    # Where the bug manifests
    crash_function: str
    crash_location: str  # file:line
    
    # Call chain from entry point
    call_chain: List[str]  # [entry, caller1, caller2, ..., crash_function]
    
    # How it happens
    reason: str
    
    # Precondition that was violated (if applicable)
    violated_precondition: Optional[Precondition] = None
    
    # Exception that would be raised
    exception_type: Optional[ExceptionType] = None
    
    # Confidence (based on how conservative the analysis was)
    confidence: float = 1.0  # 1.0 = certain, < 1.0 = may be FP

    # Quantitative reporting (barrier-compatible; does not affect verdicts)
    reachability_pts: ReachabilityIntervalPTS = field(default_factory=ReachabilityIntervalPTS.unknown)
    depth_k: Optional[int] = None
    witness: ConcreteWitnessEvidence = field(default_factory=lambda: ConcreteWitnessEvidence(present=False))
    risk_interval: Optional[RiskInterval] = None
    
    # Additional context
    tainted_sources: List[str] = field(default_factory=list)
    relevant_args: List[int] = field(default_factory=list)
    
    # Source provenance (for cleartext/sensitivity tracking)
    inferred_source: bool = False  # True if source was inferred from name/type, not explicit
    
    def __str__(self) -> str:
        chain_str = " → ".join(self.call_chain)
        return f"{self.bug_type} in {self.crash_function}: {self.reason}\n  Call chain: {chain_str}"


# ============================================================================
# VALUE STATE FOR INTERPROCEDURAL TRACKING
# ============================================================================

@dataclass
class ValueState:
    """
    Abstract state of a value for interprocedural bug detection.
    
    Tracks nullability, zero-ness, taintedness, etc.
    """
    nullability: Nullability = Nullability.TOP
    may_be_zero: bool = True
    is_tainted: bool = False
    taint_sources: Set[str] = field(default_factory=set)
    
    # Bounds info (for index values)
    may_be_negative: bool = True
    has_upper_bound: bool = False
    upper_bound: Optional[int] = None
    
    # Type info
    known_type: Optional[str] = None
    
    @classmethod
    def from_none(cls) -> 'ValueState':
        """Create state representing None."""
        return cls(nullability=Nullability.IS_NONE, may_be_zero=False)
    
    @classmethod  
    def from_literal(cls, value: Any) -> 'ValueState':
        """Create state from a literal value."""
        if value is None:
            return cls.from_none()
        state = cls(nullability=Nullability.NOT_NONE)
        if isinstance(value, (int, float)):
            state.may_be_zero = (value == 0)
            state.may_be_negative = (value < 0)
            if isinstance(value, int):
                state.has_upper_bound = True
                state.upper_bound = value
        return state
    
    def join(self, other: 'ValueState') -> 'ValueState':
        """Lattice join of two states."""
        return ValueState(
            nullability=self.nullability.join(other.nullability),
            may_be_zero=self.may_be_zero or other.may_be_zero,
            is_tainted=self.is_tainted or other.is_tainted,
            taint_sources=self.taint_sources | other.taint_sources,
            may_be_negative=self.may_be_negative or other.may_be_negative,
            has_upper_bound=self.has_upper_bound and other.has_upper_bound,
            upper_bound=min(self.upper_bound, other.upper_bound) if (self.upper_bound and other.upper_bound) else None,
        )


# ============================================================================
# INTERPROCEDURAL BUG TRACKER
# ============================================================================

@dataclass
class InterproceduralBugTracker:
    """
    Main class for interprocedural bug detection.
    
    Combines taint analysis (security bugs) with crash analysis (correctness bugs)
    to find all potential bugs reachable from program entry points.
    """
    
    # Core data
    call_graph: CallGraph
    entry_points: Set[str]
    reachable_functions: Set[str]
    
    # Summaries
    taint_summaries: Dict[str, TaintSummary] = field(default_factory=dict)
    crash_summaries: Dict[str, CrashSummary] = field(default_factory=dict)
    combined_summaries: Dict[str, InterproceduralBugSummary] = field(default_factory=dict)
    
    # Analysis state
    bugs_found: List[InterproceduralBug] = field(default_factory=list)
    analyzed: bool = False
    
    # Confidence scoring
    confidence_scorer: ConfidenceScorer = field(default_factory=ConfidenceScorer)
    
    # Intraprocedural bugs (cached)
    _intraprocedural_bugs: Dict[str, List[IntraproceduralBug]] = field(default_factory=dict)
    
    # ITERATION 518: Import aliases per file (for resolving aliased imports)
    # Maps file_path → (alias_name → real_module_path)
    # Example: "test.py" → {"ET": "xml.etree.ElementTree"}
    _import_aliases_by_file: Dict[str, Dict[str, str]] = field(default_factory=dict)
    
    @classmethod
    def from_project(cls, root_path: Path, entry_points: Optional[Set[str]] = None) -> 'InterproceduralBugTracker':
        """
        Build tracker for an entire project.
        
        Args:
            root_path: Root directory of the project
            entry_points: Optional set of entry point function names. If None, auto-detect.
                         If auto-detection finds nothing, analyze all functions.
        """
        from ..contracts.security_lattice import (
            get_source_contracts_for_summaries,
            get_sink_contracts_for_summaries,
            get_sanitizer_contracts_for_summaries,
            init_security_contracts,
        )
        
        # Initialize contracts (idempotent)
        init_security_contracts()
        
        # Build call graph
        call_graph = build_call_graph_from_directory(root_path)
        
        # Detect entry points
        if entry_points is None:
            entry_point_list = detect_entry_points_in_project(root_path)
            entry_points = get_entry_point_functions(entry_point_list)
            
            # If no entry points found, or none match actual functions,
            # use all functions as entry points
            if not entry_points or not (entry_points & set(call_graph.functions.keys())):
                entry_points = set(call_graph.functions.keys())
        
        # Compute reachable functions
        reachable = call_graph.get_reachable_from(entry_points)
        
        # If reachability is empty but we have functions, include entry points themselves
        if not reachable and entry_points:
            reachable = entry_points & set(call_graph.functions.keys())
        
        # Load security contracts for library functions
        source_contracts = get_source_contracts_for_summaries()
        sink_contracts = get_sink_contracts_for_summaries()
        sanitizer_contracts = get_sanitizer_contracts_for_summaries()
        
        # Compute taint summaries
        taint_computer = SummaryComputer(
            call_graph,
            source_contracts=source_contracts,
            sink_contracts=sink_contracts,
            sanitizer_contracts=sanitizer_contracts,
        )
        taint_summaries = taint_computer.compute_all()
        
        # Compute crash summaries (using bytecode-level analysis by default)
        crash_computer = BytecodeCrashSummaryComputer(call_graph)
        crash_summaries = crash_computer.compute_all()
        
        # Combine summaries
        combined = compute_all_bug_summaries(call_graph, taint_summaries)
        
        return cls(
            call_graph=call_graph,
            entry_points=entry_points,
            reachable_functions=reachable,
            taint_summaries=taint_summaries,
            crash_summaries=crash_summaries,
            combined_summaries=combined,
        )
    
    def _get_import_aliases_for_file(self, file_path: Path) -> Dict[str, str]:
        """
        Get or extract import aliases for a file.
        
        Caches results to avoid re-parsing.
        
        Args:
            file_path: Path to the Python file
        
        Returns:
            Dictionary mapping alias names to real module paths
            Example: {"ET": "xml.etree.ElementTree"}
        """
        file_path_str = str(file_path)
        
        # Check cache
        if file_path_str in self._import_aliases_by_file:
            return self._import_aliases_by_file[file_path_str]
        
        # Extract imports from file
        from .intraprocedural_taint import extract_module_imports
        
        try:
            source = file_path.read_text()
            code = compile(source, file_path_str, 'exec')
            import_aliases = extract_module_imports(code)
            self._import_aliases_by_file[file_path_str] = import_aliases
            return import_aliases
        except Exception as e:
            # If we can't read/compile the file, return empty dict
            self._import_aliases_by_file[file_path_str] = {}
            return {}
    
    def _compute_confidence_for_security_bug(
        self,
        bug_type: str,
        sink_type: 'SinkType',
        call_chain_length: int,
        is_internal_sink: bool = False,
    ) -> float:
        """
        Compute confidence for a security/taint bug.
        
        Args:
            bug_type: Security bug type name
            sink_type: Type of sink (SinkType enum or int)
            call_chain_length: Length of call chain
            is_internal_sink: Whether sink is in analyzed code (True) or library (False)
        
        Returns:
            Confidence score 0.0-1.0
        """
        # Without actual taint label, we use heuristics based on sink location and chain
        from ..z3model.taint_lattice import TaintLabel, SourceType, SinkType as SinkTypeEnum, CODEQL_BUG_TYPES
        
        # Convert int to SinkType if needed
        if isinstance(sink_type, int):
            try:
                sink_type = SinkTypeEnum(sink_type)
            except ValueError:
                # Invalid sink type - return conservative score
                return 0.5
        
        # Create a hypothetical "tainted" label for scoring
        # In full implementation, this would be the actual taint label at sink
        bug_def = CODEQL_BUG_TYPES.get(bug_type)
        if bug_def and bug_def.checks_sigma and not bug_def.checks_tau:
            # σ-only bugs (e.g., CLEARTEXT_LOGGING/CLEARTEXT_STORAGE) need a sensitive label,
            # otherwise scoring will early-exit at 0.0.
            label = TaintLabel.from_sensitive_source(SourceType.PASSWORD, "hypothetical")
        elif bug_def and bug_def.checks_sigma and bug_def.checks_tau:
            # Bugs requiring both τ and σ: join both kinds of evidence.
            label = TaintLabel.from_untrusted_source(SourceType.USER_INPUT, "hypothetical").join(
                TaintLabel.from_sensitive_source(SourceType.PASSWORD, "hypothetical")
            )
        else:
            label = TaintLabel.from_untrusted_source(SourceType.USER_INPUT, "hypothetical")
        
        # Score with conservative parameters
        breakdown = self.confidence_scorer.score_security_bug(
            label=label,
            sink_type=sink_type,
            is_guarded=False,  # Conservative: assume no guards
            call_chain_length=call_chain_length,
            has_exception_handler=False,  # Conservative
            in_framework_context=False,
        )
        
        score = breakdown.combined_score()
        
        # Adjust based on sink location
        if is_internal_sink:
            # Internal sink: higher confidence (we analyzed it)
            score = min(1.0, score * 1.1)
        else:
            # External/library sink: lower confidence (summaries may be incomplete)
            score = score * 0.85
        
        return score
    
    def _compute_confidence_for_error_bug(
        self,
        bug_type: str,
        call_chain_length: int,
        certainty: str = 'POSSIBLE',
    ) -> float:
        """
        Compute confidence for an error bug (crash/exception).
        
        Args:
            bug_type: Error bug type name
            call_chain_length: Length of call chain
            certainty: Certainty level ('DEFINITE', 'LIKELY', 'POSSIBLE', 'UNKNOWN')
        
        Returns:
            Confidence score 0.0-1.0
        """
        breakdown = self.confidence_scorer.score_error_bug(
            bug_type=bug_type,
            certainty=certainty,
            is_guarded=False,  # Conservative
            call_chain_length=call_chain_length,
            has_exception_handler=False,  # Conservative
        )
        
        return breakdown.combined_score()
    
    def find_all_bugs(self, apply_fp_reduction: bool = False) -> List[InterproceduralBug]:
        """
        Find all bugs reachable from entry points.
        
        Performs interprocedural analysis starting from each entry point,
        tracking value states and checking for precondition violations.
        
        Deduplicates findings by (file, line, sink_type) to avoid reporting
        the same bug multiple times from different entry points.
        
        Args:
            apply_fp_reduction: If True, apply FP context adjustments to reduce
                               false positives from CLI tools, test files, etc.
        """
        self.bugs_found = []
        
        # ITERATION 610: For crash bugs, analyze ALL functions with may_trigger
        # Crash bugs don't require entry-point reachability - if a function CAN crash,
        # we should report it regardless of how it's called. Security bugs still
        # require reachability for taint tracking.
        self._analyze_all_crash_bugs()
        
        # For security bugs, use entry-point reachability
        for entry in self.entry_points:
            self._analyze_from_entry(entry)
        
        # Deduplicate bugs by (location, bug_type)
        # Keep the bug with the shortest call chain for each unique location+type
        self.bugs_found = self._deduplicate_bugs(self.bugs_found)
        
        # Apply FP context adjustments
        if apply_fp_reduction:
            self.bugs_found = self._apply_fp_context_adjustments(self.bugs_found)
        
        self.analyzed = True
        return self.bugs_found
    
    def _analyze_all_crash_bugs(self) -> None:
        """
        Analyze ALL functions for crash bugs, regardless of reachability.
        
        Crash bugs (DIV_ZERO, NULL_PTR, BOUNDS, etc.) are about whether a function
        CAN crash, not whether it's reachable from entry points. This differs from
        security bugs which require taint to flow from sources to sinks.
        """
        for func_name, crash_summary in self.crash_summaries.items():
            # Only analyze functions that have direct may_trigger bugs
            if not crash_summary.may_trigger:
                continue
            
            func_info = self.call_graph.get_function(func_name)
            
            # Create a simple call chain with just this function
            call_chain = [func_name]
            
            # Check for direct bugs in this function
            self._check_direct_bugs(crash_summary, call_chain, func_info)
    
    def _apply_fp_context_adjustments(
        self,
        bugs: List[InterproceduralBug],
        min_confidence: float = 0.40,
    ) -> List[InterproceduralBug]:
        """
        Apply FP context adjustments to reduce false positives.
        
        Analyzes each bug's context (source types, file path, call chain)
        and adjusts confidence accordingly. Filters out low-confidence bugs.
        
        Args:
            bugs: List of bugs to process
            min_confidence: Minimum confidence to keep (default 0.40)
        
        Returns:
            Filtered list of bugs with adjusted confidence
        """
        from ..fp_context import (
            FPContextDetector,
            adjust_confidence_for_context,
        )
        
        detector = FPContextDetector()
        filtered_bugs = []
        
        for bug in bugs:
            # Extract file path from crash_location
            file_path = None
            if ':' in bug.crash_location:
                file_path = bug.crash_location.rsplit(':', 1)[0]
            
            # Get tainted sources from bug
            tainted_sources = list(bug.tainted_sources) if bug.tainted_sources else []
            
            # Also extract source info from reason string
            if 'from' in bug.reason.lower():
                # Extract source from patterns like "Tainted data from os.environ.get(...)"
                tainted_sources.append(bug.reason)
            
            # Detect contexts
            context_result = detector.detect_contexts(
                bug_type=bug.bug_type,
                tainted_sources=tainted_sources,
                file_path=file_path,
                call_chain=bug.call_chain,
                sink_function=bug.crash_function,
            )
            
            # Apply confidence adjustment
            original_confidence = bug.confidence
            adjusted_confidence = original_confidence * context_result.confidence_multiplier

            # Record as a (conditional) risk bound driven by context priors.
            # This is metadata only; reachability is unchanged.
            bug.risk_interval = RiskInterval(
                risk_lb=0.0,
                risk_ub=max(0.0, min(1.0, adjusted_confidence)),
                threat_model_id="fp_context_v1",
                evidence=context_result.reasons.copy(),
            )
            
            # Update bug's confidence
            bug.confidence = adjusted_confidence
            
            # Filter out low-confidence bugs
            if adjusted_confidence >= min_confidence:
                filtered_bugs.append(bug)
        
        return filtered_bugs
    
    def _deduplicate_bugs(self, bugs: List[InterproceduralBug]) -> List[InterproceduralBug]:
        """
        Deduplicate bugs by (file:line, bug_type).
        
        For each unique (location, bug_type) pair, keep only the bug with:
        1. Shortest call chain (most direct path to bug)
        2. Highest confidence if call chains are equal length
        
        Args:
            bugs: List of bugs to deduplicate
        
        Returns:
            Deduplicated list of bugs
        """
        from collections import defaultdict
        
        # Group bugs by (location, bug_type)
        bug_groups: Dict[Tuple[str, str], List[InterproceduralBug]] = defaultdict(list)
        
        for bug in bugs:
            key = (bug.crash_location, bug.bug_type)
            bug_groups[key].append(bug)
        
        # For each group, keep only the best bug
        deduplicated = []
        for (location, bug_type), group in bug_groups.items():
            # Sort by: (1) call chain length (shorter is better), (2) confidence (higher is better)
            best_bug = min(
                group,
                key=lambda b: (len(b.call_chain), -b.confidence)
            )
            deduplicated.append(best_bug)
        
        # Sort for stable output
        deduplicated.sort(key=lambda b: (b.crash_location, b.bug_type))
        
        return deduplicated
    
    def _analyze_from_entry(self, entry_func: str) -> None:
        """Analyze all paths from an entry point."""
        # BFS/DFS through call graph
        visited: Set[Tuple[str, ...]] = set()
        worklist: List[Tuple[List[str], Dict[str, ValueState]]] = [
            ([entry_func], {})
        ]
        
        while worklist:
            call_chain, context = worklist.pop()
            current_func = call_chain[-1]
            
            # Avoid infinite loops on recursion
            chain_key = tuple(call_chain)
            if chain_key in visited:
                continue
            visited.add(chain_key)
            
            # Limit call chain depth
            if len(call_chain) > 20:
                continue
            
            # Get summary for current function
            crash_summary = self.crash_summaries.get(current_func)
            taint_summary = self.taint_summaries.get(current_func)
            
            # Get function info for file path context
            func_info = self.call_graph.get_function(current_func)
            
            # Check for direct bugs in this function
            if crash_summary:
                self._check_direct_bugs(crash_summary, call_chain, func_info)
            
            # Check for taint/security bugs in this function
            if taint_summary:
                self._check_taint_bugs(taint_summary, call_chain, func_info)
            
            # NEW: Run intraprocedural analysis for this function
            # This detects bugs within the function body via dataflow
            self._check_intraprocedural_bugs(current_func, call_chain)
            if func_info:
                for call_site in func_info.call_sites:
                    callee = call_site.callee_name
                    
                    # Check for external/library function sinks (e.g., print, logging.*)
                    if callee and callee not in self.call_graph.functions:
                        self._check_external_sink(callee, call_site, call_chain)
                    
                    if callee and callee in self.reachable_functions:
                        # Check if this call may trigger bugs
                        callee_summary = self.crash_summaries.get(callee)
                        if callee_summary:
                            self._check_call_site_bugs(
                                call_chain, call_site, callee_summary, context
                            )
                        
                        # Continue analysis into callee
                        new_chain = call_chain + [callee]
                        worklist.append((new_chain, context.copy()))
    
    def _check_direct_bugs(
        self,
        summary: CrashSummary,
        call_chain: List[str],
        func_info: Optional['FunctionInfo'] = None,
    ) -> None:
        """Check for bugs directly triggered by a function."""
        from ..cfg.call_graph import FunctionInfo
        func_name = summary.qualified_name
        
        # Build crash_location with file path if available
        if func_info:
            crash_location = f"{func_info.file_path}:{func_info.line_number}"
        else:
            crash_location = f"{summary.function_name}"
        
        for bug_type in summary.may_trigger:
            # Determine certainty based on bug type
            # NULL_PTR and BOUNDS have higher false positive rates due to
            # path infeasibility and unmodeled invariants
            if bug_type in ('NULL_PTR', 'BOUNDS'):
                certainty = 'POSSIBLE'  # Conservative: may-analysis, not must-analysis
            else:
                certainty = 'LIKELY'  # Direct triggers are likely for other bug types
            
            # Compute confidence for this error bug
            confidence = self._compute_confidence_for_error_bug(
                bug_type=bug_type,
                call_chain_length=len(call_chain),
                certainty=certainty,
            )
            
            # ITERATION 609: Reduce confidence for guarded bugs
            # If this bug type has guards (e.g., null checks, bounds checks),
            # the code has SOME protection, reducing the likelihood it's a real bug
            # ITERATION 610: Increased reduction - if ALL paths are guarded for this bug type,
            # it's very likely a false positive (e.g., attribute access on typed params)
            if bug_type in summary.guarded_bugs:
                # Check if may_trigger ONLY has this bug type due to untracked paths
                # In practice, if guarded_bugs contains the bug type, it means at least
                # some paths have guards, making it less likely to be a real bug
                confidence *= 0.3  # 70% reduction for guarded operations
            
            # bug_type is now a string (e.g., 'DIV_ZERO')
            bug = InterproceduralBug(
                bug_type=bug_type,
                crash_function=func_name,
                crash_location=crash_location,
                call_chain=call_chain.copy(),
                reason=f"Function may trigger {bug_type}" + (" (guarded)" if bug_type in summary.guarded_bugs else ""),
                confidence=confidence,
                reachability_pts=ReachabilityIntervalPTS.unknown(
                    evidence=["source=crash_summary", "kind=may_trigger"]
                ),
            )
            
            # Check for relevant exceptions
            for exc, mapped_bug in EXCEPTION_TO_BUG.items():
                if mapped_bug == bug_type and exc in summary.may_raise:
                    bug.exception_type = exc
                    break
            
            self.bugs_found.append(bug)
    
    def _check_taint_bugs(
        self,
        taint_summary: 'TaintSummary',
        call_chain: List[str],
        func_info: Optional['FunctionInfo'] = None,
    ) -> None:
        """Check for taint/security bugs in a function based on its taint summary."""
        from ..z3model.taint_lattice import CODEQL_BUG_TYPES
        from ..contracts.security_lattice import get_sink_contracts
        from ..cfg.call_graph import FunctionInfo
        import os
        
        DEBUG = os.environ.get('DEBUG_TAINT_SUMMARY') == '1'
        
        func_name = taint_summary.function_name
        
        # Build crash_location with file path if available
        if func_info:
            crash_location = f"{func_info.file_path}:{func_info.line_number}"
        else:
            crash_location = f"{func_name}"
        
        # Check if this function is a sink (may have multiple sink types)
        if taint_summary.dependency.is_sink and taint_summary.dependency.sink_types:
            # Iterate over all sink types this function has
            for sink_type in taint_summary.dependency.sink_types:
                # sink_type is stored as an int in summaries; normalize for comparisons.
                from ..z3model.taint_lattice import SinkType as SinkTypeEnum
                sink_type_int = sink_type.value if hasattr(sink_type, "value") else int(sink_type)
                try:
                    sink_type_enum = SinkTypeEnum(sink_type_int)
                except Exception:
                    continue

                # ITERATION 604: Check if this sink has context-dependent safety
                # ITERATION 605: Check ALL contracts for this sink_type, not just the function
                # For sinks with parameterized_check, shell_check, etc., the summary
                # cannot determine safety without call-site context. Skip summary-based
                # reporting and let intraprocedural analysis handle it.
                
                # Get all sink contracts for this sink_type across all functions
                from pyfromscratch.contracts.security_lattice import get_all_sink_contracts
                all_sink_contracts = get_all_sink_contracts()
                
                if DEBUG:
                    print(f"[TAINT_SUMMARY] _check_taint_bugs for {func_name}, sink_type={sink_type}")
                    print(f"[TAINT_SUMMARY]   Checking contracts for sink_type {sink_type}")
                
                # Check if ANY contract for this sink_type has context-dependent checks
                has_context_dependent_check = any(
                    (c.parameterized_check or c.shell_check or c.loader_check or c.entity_check)
                    for c in all_sink_contracts if int(getattr(c.sink_type, "value", c.sink_type)) == sink_type_int
                )
                
                if DEBUG:
                    print(f"[TAINT_SUMMARY]   has_context_dependent_check={has_context_dependent_check}")
                
                if has_context_dependent_check:
                    # Skip summary-based reporting for context-dependent sinks
                    # The intraprocedural analysis will check these properly
                    if DEBUG:
                        print(f"[TAINT_SUMMARY]   Skipping summary-based reporting (context-dependent sink)")
                    continue
                
                # Map sink_type to security bug types
                for bug_name, bug_def in CODEQL_BUG_TYPES.items():
                    if bug_def.sink_type == sink_type_enum:
                        # ITERATION 607: Check if ANY parameters flow to this sink
                        # If params_to_sinks is empty or doesn't have this sink_type,
                        # then no parameters flow unsanitized to this sink -> no bug
                        if sink_type_int not in taint_summary.dependency.params_to_sinks:
                            # No parameters flow to this sink (empty or all sanitized)
                            if DEBUG:
                                print(f"[TAINT_SUMMARY]   Skipping {bug_name}: no params flow to sink {sink_type_enum.name}")
                            continue
                        
                        param_indices = taint_summary.dependency.params_to_sinks[sink_type_int]
                        if not param_indices:
                            # Empty set - all parameters are sanitized for this sink
                            if DEBUG:
                                print(f"[TAINT_SUMMARY]   Skipping {bug_name}: params sanitized for sink {sink_type_enum.name}")
                            continue
                        
                        # ITERATION 497: For σ-only bugs, check if sensitive data actually reaches the sink
                        is_sigma_only_bug = bug_def.checks_sigma and not bug_def.checks_tau
                        
                        if is_sigma_only_bug:
                            # Check if we have evidence of sensitive data reaching this sink
                            has_sigma_evidence = False
                            
                            # Check if this sink is called with sensitive parameters
                            # (e.g., does the function have σ-tainted params that flow to this sink)
                            for param_idx in param_indices:
                                if taint_summary.sigma_contribution.get(param_idx, False):
                                    # Found a sensitive parameter flowing to this sink!
                                    has_sigma_evidence = True
                                    break

                            # Virtual index -1 means an internal taint source flows to this sink.
                            # For σ-only bugs, accept this as sensitive evidence if the function
                            # itself introduces a sensitive source (e.g., getpass.getpass()).
                            if not has_sigma_evidence and (-1 in param_indices):
                                try:
                                    from ..z3model.taint_lattice import SENSITIVE_SOURCES_MASK
                                    st = taint_summary.dependency.source_type
                                    if st is not None and ((1 << int(st)) & SENSITIVE_SOURCES_MASK) != 0:
                                        has_sigma_evidence = True
                                except Exception:
                                    pass
                            
                            if not has_sigma_evidence:
                                # No evidence of sensitive data reaching this sink
                                # Skip to avoid false positive
                                if DEBUG:
                                    print(f"[TAINT_SUMMARY]   Skipping {bug_name}: no sensitive data reaches sink")
                                continue
                        
                        # Compute confidence for this security bug
                        confidence = self._compute_confidence_for_security_bug(
                            bug_type=bug_name,
                            sink_type=sink_type,
                            call_chain_length=len(call_chain),
                            is_internal_sink=True,  # This is in analyzed code
                        )
                        
                        # ITERATION 483: Reduce confidence for σ-only bugs at summary level
                        # The intraprocedural analyzer will provide precise σ tracking
                        if is_sigma_only_bug:
                            confidence *= 0.5  # Lower confidence, may be refined by intraprocedural pass
                        
                        # This function is a sink for this bug type
                        bug = InterproceduralBug(
                            bug_type=bug_name,
                            crash_function=func_name,
                            crash_location=crash_location,
                            call_chain=call_chain.copy(),
                            reason=f"Function is a {bug_name} sink (sink_type={sink_type_enum.name})",
                            confidence=confidence,
                            reachability_pts=ReachabilityIntervalPTS.unknown(
                                evidence=["source=taint_summary", "kind=sink_summary"]
                            ),
                        )
                        self.bugs_found.append(bug)
    
    def _check_external_sink(
        self,
        callee_name: str,
        call_site: 'CallSite',
        call_chain: List[str],
    ) -> None:
        """
        Check if an external function is a security sink.
        
        ITERATION 451: Now properly handles σ-only bugs (CLEARTEXT_LOGGING, CLEARTEXT_STORAGE)
        by checking if the caller's taint summary shows sensitive data flowing to the sink.
        
        ITERATION 604: Skip context-dependent sinks (parameterized queries, shell=False, etc.)
        These require call-site analysis which we can't do from summaries alone.
        """
        from ..contracts.security_lattice import get_sink_contracts
        from ..z3model.taint_lattice import CODEQL_BUG_TYPES
        import os
        
        DEBUG = os.environ.get('DEBUG_EXTERNAL_SINK') == '1'
        
        # Check if this function has a sink contract
        sink_contracts = get_sink_contracts(callee_name)
        
        if DEBUG and sink_contracts:
            print(f"[EXTERNAL_SINK] _check_external_sink for {callee_name}")
            print(f"[EXTERNAL_SINK]   Found {len(sink_contracts)} contracts")
            print(f"[EXTERNAL_SINK]   call_chain: {call_chain}")
        
        # Get the caller's taint summary to check σ tracking
        caller_name = call_chain[-1]
        caller_summary = self.taint_summaries.get(caller_name)
        
        for contract in sink_contracts:
            # ITERATION 604: Skip context-dependent sinks
            # These sinks (parameterized queries, shell=False, etc.) require call-site
            # analysis to determine safety. Summary-based interprocedural analysis
            # cannot determine this context, so we skip them here and let
            # intraprocedural analysis handle them.
            if contract.parameterized_check or contract.shell_check or contract.loader_check or contract.entity_check:
                if DEBUG:
                    print(f"[EXTERNAL_SINK]   Skipping context-dependent sink: {contract.function_id}")
                continue
            
            # This is a known sink - report as potential security bug
            sink_type = contract.sink_type
            # This is a known sink - report as potential security bug
            sink_type = contract.sink_type
            
            # Find associated bug types
            for bug_name, bug_def in CODEQL_BUG_TYPES.items():
                if bug_def.sink_type == sink_type:
                    # ITERATION 607: Check if ANY parameters flow to this sink
                    # Only report if tainted parameters actually reach this external sink
                    if caller_summary:
                        # Check if this sink type has any parameters flowing to it
                        if sink_type not in caller_summary.dependency.params_to_sinks:
                            # No parameters flow to this sink type
                            if DEBUG:
                                print(f"[EXTERNAL_SINK]   Skipping {bug_name}: no params flow to sink {sink_type.name}")
                            continue
                        
                        param_indices = caller_summary.dependency.params_to_sinks[sink_type]
                        if not param_indices:
                            # Empty set - all parameters are sanitized for this sink
                            if DEBUG:
                                print(f"[EXTERNAL_SINK]   Skipping {bug_name}: params sanitized for sink {sink_type.name}")
                            continue
                    
                    # ITERATION 451: Handle σ-only checks with interprocedural σ tracking
                    if bug_def.checks_sigma and not bug_def.checks_tau:
                        # This is a σ-only check (e.g., CLEARTEXT_LOGGING, CLEARTEXT_STORAGE)
                        # Check if we have evidence of sensitive data reaching this sink
                        has_sigma_evidence = False
                        
                        if caller_summary:
                            # Check if sensitive data flows to this external sink call
                            # The call_site would need to be analyzed to determine which params
                            # are used as arguments. For now, check if ANY parameter with σ
                            # flows to a sink of this type in the caller.
                            param_indices = caller_summary.dependency.params_to_sinks.get(sink_type, set())
                            for param_idx in param_indices:
                                if caller_summary.sigma_contribution.get(param_idx, False):
                                    # Found a sensitive parameter flowing to this sink!
                                    has_sigma_evidence = True
                                    break
                        
                        if not has_sigma_evidence:
                            # No evidence of sensitive data reaching this sink
                            # Skip to avoid false positive
                            if DEBUG:
                                print(f"[EXTERNAL_SINK]   Skipping {bug_name}: no sensitive data reaches sink")
                            continue
                    
                    # Compute confidence for external sink
                    confidence = self._compute_confidence_for_security_bug(
                        bug_type=bug_name,
                        sink_type=sink_type,
                        call_chain_length=len(call_chain),
                        is_internal_sink=False,  # External/library sink
                    )
                    
                    bug = InterproceduralBug(
                        bug_type=bug_name,
                        crash_function=call_chain[-1],
                        crash_location=f"{call_site.file_path}:{call_site.line_number}",
                        call_chain=call_chain.copy(),
                        reason=f"Call to {callee_name} at {bug_name} sink (sink_type={sink_type.name})",
                        confidence=confidence,
                        reachability_pts=ReachabilityIntervalPTS.unknown(
                            evidence=["source=external_sink_summary", f"callee={callee_name}"]
                        ),
                    )
                    self.bugs_found.append(bug)
    
    def _check_intraprocedural_bugs(
        self,
        func_name: str,
        call_chain: List[str],
    ) -> None:
        """
        Run intraprocedural taint analysis on a function.
        
        This detects bugs within the function body via detailed dataflow analysis,
        complementing the summary-based interprocedural analysis.
        """
        # Check cache first
        if func_name in self._intraprocedural_bugs:
            bugs = self._intraprocedural_bugs[func_name]
        else:
            # Get function info
            func_info = self.call_graph.get_function(func_name)
            if not func_info or not func_info.code_object:
                return
            
            # ITERATION 518: Get import aliases for this file
            import_aliases = self._get_import_aliases_for_file(func_info.file_path)
            
            # Run intraprocedural analysis
            try:
                analyzer = IntraproceduralTaintAnalyzer(
                    code_obj=func_info.code_object,
                    function_name=func_name,
                    file_path=str(func_info.file_path),
                    import_aliases=import_aliases,
                )
                bugs = analyzer.analyze()
                self._intraprocedural_bugs[func_name] = bugs
            except Exception as e:
                # Gracefully handle analysis failures
                print(f"Warning: Intraprocedural analysis failed for {func_name}: {e}")
                self._intraprocedural_bugs[func_name] = []
                return
        
        # Convert intraprocedural bugs to interprocedural bugs with call chain
        for intra_bug in bugs:
            # Create interprocedural bug with full call chain
            inter_bug = InterproceduralBug(
                bug_type=intra_bug.bug_type,
                crash_function=func_name,
                crash_location=f"{intra_bug.file_path}:{intra_bug.line_number}",
                call_chain=call_chain.copy(),
                reason=intra_bug.reason,
                confidence=intra_bug.confidence,
                inferred_source=intra_bug.inferred_source,
                reachability_pts=ReachabilityIntervalPTS.unknown(
                    evidence=["source=intraprocedural_taint"]
                ),
            )
            self.bugs_found.append(inter_bug)
    
    def _check_call_site_bugs(
        self,
        call_chain: List[str],
        call_site: CallSite,
        callee_summary: CrashSummary,
        context: Dict[str, ValueState],
    ) -> None:
        """Check for bugs at a specific call site."""
        caller = call_chain[-1]
        callee = callee_summary.qualified_name
        
        # Check precondition violations
        for precond in callee_summary.preconditions:
            # For each precondition, check if caller may violate it
            bug = self._check_precondition(
                precond, call_chain, call_site, callee_summary, context
            )
            if bug:
                self.bugs_found.append(bug)
        
        # Check for unhandled exceptions from callee
        caller_summary = self.crash_summaries.get(caller)
        if caller_summary:
            # Exceptions raised by callee that propagate up
            for exc in callee_summary.may_raise:
                if exc in EXCEPTION_TO_BUG:
                    bug_type = EXCEPTION_TO_BUG[exc]  # Now returns string
                    
                    # Compute confidence for exception propagation
                    confidence = self._compute_confidence_for_error_bug(
                        bug_type=bug_type,
                        call_chain_length=len(call_chain) + 1,
                        certainty='POSSIBLE',  # May be caught
                    )
                    
                    # ITERATION 610: Reduce confidence if this exception comes from a guarded operation
                    # If the callee has guarded_bugs for this type, the exception is likely
                    # from controlled/expected code paths, not actual bugs
                    if bug_type in callee_summary.guarded_bugs:
                        confidence *= 0.3  # Same reduction as direct guarded bugs
                    
                    bug = InterproceduralBug(
                        bug_type=bug_type,
                        crash_function=callee,
                        crash_location=f"{call_site.file_path}:{call_site.line_number}",
                        call_chain=call_chain + [callee],
                        reason=f"Call to {callee} may raise {exc.name}",
                        exception_type=exc,
                        confidence=confidence,
                    )
                    self.bugs_found.append(bug)
    
    def _check_precondition(
        self,
        precond: Precondition,
        call_chain: List[str],
        call_site: CallSite,
        callee_summary: CrashSummary,
        context: Dict[str, ValueState],
    ) -> Optional[InterproceduralBug]:
        """Check if a precondition may be violated at a call site."""
        callee = callee_summary.qualified_name
        
        # Use PRECONDITION_TO_BUG from crash_summaries (now returns strings)
        bug_type = PRECONDITION_TO_BUG.get(precond.condition_type, 'PANIC')
        
        # Check if we have arg info
        arg_idx = precond.param_index
        
        # Compute confidence for precondition violation
        confidence = self._compute_confidence_for_error_bug(
            bug_type=bug_type,
            call_chain_length=len(call_chain) + 1,
            certainty='POSSIBLE',  # Preconditions are uncertain
        )
        
        # Create bug report
        return InterproceduralBug(
            bug_type=bug_type,
            crash_function=callee,
            crash_location=f"{call_site.file_path}:{call_site.line_number}",
            call_chain=call_chain + [callee],
            reason=f"Argument {arg_idx} may violate {precond}",
            violated_precondition=precond,
            relevant_args=[arg_idx],
            confidence=confidence,
            reachability_pts=ReachabilityIntervalPTS.unknown(
                evidence=["source=precondition_check", f"precond={precond.condition_type.name}"]
            ),
        )
    
    # ========================================================================
    # QUERY INTERFACE
    # ========================================================================
    
    def get_bugs_by_type(self, bug_type: str) -> List[InterproceduralBug]:
        """Get all bugs of a specific type (by string name)."""
        return [b for b in self.bugs_found if b.bug_type == bug_type]
    
    def get_bugs_in_function(self, func_name: str) -> List[InterproceduralBug]:
        """Get all bugs in a specific function."""
        return [b for b in self.bugs_found if b.crash_function == func_name]
    
    def get_security_bugs(self) -> List[InterproceduralBug]:
        """Get all security-related bugs."""
        security_types = {
            'SQL_INJECTION', 'COMMAND_INJECTION', 'CODE_INJECTION',
            'PATH_INJECTION', 'LDAP_INJECTION', 'XPATH_INJECTION',
            'NOSQL_INJECTION', 'REGEX_INJECTION', 'URL_REDIRECT',
            'HEADER_INJECTION', 'COOKIE_INJECTION', 'REFLECTED_XSS',
            'SSRF', 'UNSAFE_DESERIALIZATION', 'XXE',
            'CLEARTEXT_LOGGING', 'CLEARTEXT_STORAGE',
        }
        return [b for b in self.bugs_found if b.bug_type in security_types]
    
    def get_crash_bugs(self) -> List[InterproceduralBug]:
        """Get all crash-inducing bugs."""
        crash_types = {
            'NULL_PTR', 'BOUNDS', 'DIV_ZERO',
            'TYPE_CONFUSION', 'ASSERT_FAIL', 'PANIC',
            'STACK_OVERFLOW', 'INTEGER_OVERFLOW', 'FP_DOMAIN',
        }
        return [b for b in self.bugs_found if b.bug_type in crash_types]
    
    def get_high_confidence_bugs(self, threshold: float = 0.7) -> List[InterproceduralBug]:
        """Get bugs with confidence above threshold."""
        return [b for b in self.bugs_found if b.confidence >= threshold]
    
    def summary_report(self) -> str:
        """Generate a summary report of all found bugs."""
        if not self.analyzed:
            return "Analysis not yet run. Call find_all_bugs() first."
        
        lines = [
            "=" * 60,
            "INTERPROCEDURAL BUG ANALYSIS REPORT",
            "=" * 60,
            f"Entry points analyzed: {len(self.entry_points)}",
            f"Reachable functions: {len(self.reachable_functions)}",
            f"Total bugs found: {len(self.bugs_found)}",
            "",
            "BUGS BY TYPE:",
            "-" * 40,
        ]
        
        # Count by type (bug_type is now a string)
        type_counts: Dict[str, int] = {}
        for bug in self.bugs_found:
            type_counts[bug.bug_type] = type_counts.get(bug.bug_type, 0) + 1
        
        for bug_type, count in sorted(type_counts.items(), key=lambda x: -x[1]):
            lines.append(f"  {bug_type}: {count}")
        
        lines.extend([
            "",
            "HIGH CONFIDENCE BUGS (>= 0.7):",
            "-" * 40,
        ])
        
        for bug in self.get_high_confidence_bugs():
            lines.append(f"  [{bug.confidence:.1f}] {bug}")
        
        return "\n".join(lines)


# ============================================================================
# CONVENIENCE FUNCTIONS
# ============================================================================

def analyze_project_for_all_bugs(root_path: Path) -> Tuple[List[InterproceduralBug], str]:
    """
    Analyze a project for ALL bug types.
    
    Returns (list of bugs, summary report).
    """
    tracker = InterproceduralBugTracker.from_project(root_path)
    bugs = tracker.find_all_bugs()
    report = tracker.summary_report()
    return bugs, report


def analyze_file_for_bugs(file_path: Path) -> List[InterproceduralBug]:
    """Analyze a single file for bugs."""
    # Create minimal tracker for single file
    from ..cfg.call_graph import build_call_graph_from_file
    from ..contracts.security_lattice import (
        get_source_contracts_for_summaries,
        get_sink_contracts_for_summaries,
        get_sanitizer_contracts_for_summaries,
        init_security_contracts,
    )
    
    # Initialize contracts (idempotent)
    init_security_contracts()
    
    call_graph = build_call_graph_from_file(file_path)
    
    # All functions are entry points for single-file analysis
    entry_points = set(call_graph.functions.keys())
    reachable = entry_points.copy()
    
    # Load security contracts for library functions
    source_contracts = get_source_contracts_for_summaries()
    sink_contracts = get_sink_contracts_for_summaries()
    sanitizer_contracts = get_sanitizer_contracts_for_summaries()
    
    # Compute summaries (using bytecode-level analysis)
    crash_computer = BytecodeCrashSummaryComputer(call_graph)
    crash_summaries = crash_computer.compute_all()
    
    taint_computer = SummaryComputer(
        call_graph,
        source_contracts=source_contracts,
        sink_contracts=sink_contracts,
        sanitizer_contracts=sanitizer_contracts,
    )
    taint_summaries = taint_computer.compute_all()
    
    combined = compute_all_bug_summaries(call_graph, taint_summaries)
    
    tracker = InterproceduralBugTracker(
        call_graph=call_graph,
        entry_points=entry_points,
        reachable_functions=reachable,
        taint_summaries=taint_summaries,
        crash_summaries=crash_summaries,
        combined_summaries=combined,
    )
    
    return tracker.find_all_bugs()


# ============================================================================
# EXPORTS
# ============================================================================

__all__ = [
    'InterproceduralBug',
    'ValueState',
    'InterproceduralBugTracker',
    'analyze_project_for_all_bugs',
    'analyze_file_for_bugs',
]
