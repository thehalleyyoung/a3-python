"""Barriers: inductive invariants, templates, synthesis, ranking functions."""

from .invariants import (
    BarrierFunction,
    BarrierCertificate,
    InductivenessResult,
    InductivenessChecker,
    linear_combination_barrier,
)

from .templates import (
    stack_depth_barrier,
    variable_upper_bound_barrier,
    variable_lower_bound_barrier,
    variable_range_barrier,
    iteration_count_barrier,
    constant_barrier,
    conjunction_barrier,
    extract_local_variable,
    conditional_guard_barrier,
    loop_range_barrier,
    disjunction_barrier,
    collection_size_barrier,
    progress_measure_barrier,
    invariant_region_barrier,
)

from .synthesis import (
    SynthesisConfig,
    SynthesisResult,
    BarrierSynthesizer,
    synthesize_barrier_for_bug_type,
)

from .ranking import (
    RankingFunction,
    RankingFunctionCertificate,
    TerminationProofResult,
    TerminationChecker,
    linear_ranking_function,
    simple_counter_ranking,
    lexicographic_ranking,
)

from .cegis import (
    CEGISConfig,
    CEGISResult,
    CEGISBarrierSynthesizer,
    synthesize_barrier_cegis,
    Counterexample,
)

__all__ = [
    # Core infrastructure
    'BarrierFunction',
    'BarrierCertificate',
    'InductivenessResult',
    'InductivenessChecker',
    'linear_combination_barrier',
    # Templates
    'stack_depth_barrier',
    'variable_upper_bound_barrier',
    'variable_lower_bound_barrier',
    'variable_range_barrier',
    'iteration_count_barrier',
    'constant_barrier',
    'conjunction_barrier',
    'extract_local_variable',
    'conditional_guard_barrier',
    'loop_range_barrier',
    'disjunction_barrier',
    'collection_size_barrier',
    'progress_measure_barrier',
    'invariant_region_barrier',
    # Synthesis
    'SynthesisConfig',
    'SynthesisResult',
    'BarrierSynthesizer',
    'synthesize_barrier_for_bug_type',
    # Ranking functions (termination)
    'RankingFunction',
    'RankingFunctionCertificate',
    'TerminationProofResult',
    'TerminationChecker',
    'linear_ranking_function',
    'simple_counter_ranking',
    'lexicographic_ranking',
    # CEGIS (CounterExample-Guided Inductive Synthesis)
    'CEGISConfig',
    'CEGISResult',
    'CEGISBarrierSynthesizer',
    'synthesize_barrier_cegis',
    'Counterexample',
]
