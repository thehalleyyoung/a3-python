#!/usr/bin/env python3
"""
Trace which of the 25 papers are actually being called during verification.

This instruments the verification pipeline to log every paper invocation
and measure its contribution to FP detection.
"""

import pickle
import sys
from collections import defaultdict
from contextlib import contextmanager
import time

# Global tracking
PAPER_CALLS = defaultdict(int)
PAPER_TIMES = defaultdict(float)
PAPER_FPS_FOUND = defaultdict(int)

class PaperTracer:
    """Trace paper invocations."""
    
    def __init__(self):
        self.current_bug = None
        self.call_stack = []
    
    @contextmanager
    def trace_paper(self, paper_num: int, paper_name: str):
        """Context manager to trace a paper invocation."""
        PAPER_CALLS[paper_num] += 1
        self.call_stack.append((paper_num, paper_name))
        
        start = time.time()
        proved_safe = False
        
        try:
            yield
        except Exception as e:
            # Paper failed
            pass
        finally:
            elapsed = time.time() - start
            PAPER_TIMES[paper_num] += elapsed
            self.call_stack.pop()
    
    def mark_fp_found(self, paper_num: int):
        """Mark that this paper found an FP."""
        PAPER_FPS_FOUND[paper_num] += 1

# Global tracer
TRACER = PaperTracer()

def inject_tracing():
    """Inject tracing into all paper implementations."""
    
    # Patch Layer 0 (Papers #21-25)
    from pyfromscratch.barriers import fast_barrier_filters
    
    original_likely_invariants = fast_barrier_filters.LikelyInvariantDetector.proves_safe
    def traced_likely_invariants(self, *args, **kwargs):
        with TRACER.trace_paper(21, "Likely Invariants"):
            result = original_likely_invariants(self, *args, **kwargs)
            if result[0]:  # is_safe
                TRACER.mark_fp_found(21)
            return result
    fast_barrier_filters.LikelyInvariantDetector.proves_safe = traced_likely_invariants
    
    original_separation = fast_barrier_filters.SeparationLogicVerifier.proves_safe
    def traced_separation(self, *args, **kwargs):
        with TRACER.trace_paper(22, "Separation Logic"):
            result = original_separation(self, *args, **kwargs)
            if result[0]:
                TRACER.mark_fp_found(22)
            return result
    fast_barrier_filters.SeparationLogicVerifier.proves_safe = traced_separation
    
    original_refinement = fast_barrier_filters.RefinementTypeVerifier.proves_safe
    def traced_refinement(self, *args, **kwargs):
        with TRACER.trace_paper(23, "Refinement Types"):
            result = original_refinement(self, *args, **kwargs)
            if result[0]:
                TRACER.mark_fp_found(23)
            return result
    fast_barrier_filters.RefinementTypeVerifier.proves_safe = traced_refinement
    
    original_interval = fast_barrier_filters.FastIntervalAnalysis.proves_safe
    def traced_interval(self, *args, **kwargs):
        with TRACER.trace_paper(24, "Interval Analysis"):
            result = original_interval(self, *args, **kwargs)
            if result[0]:
                TRACER.mark_fp_found(24)
            return result
    fast_barrier_filters.FastIntervalAnalysis.proves_safe = traced_interval
    
    original_stochastic = fast_barrier_filters.StochasticBarrierSynthesis.proves_safe
    def traced_stochastic(self, *args, **kwargs):
        with TRACER.trace_paper(25, "Stochastic Barriers"):
            result = original_stochastic(self, *args, **kwargs)
            if result[0]:
                TRACER.mark_fp_found(25)
            return result
    fast_barrier_filters.StochasticBarrierSynthesis.proves_safe = traced_stochastic
    
    # Patch Papers #1-5
    try:
        from pyfromscratch.barriers import papers_1_to_5_complete
        
        # Paper #1: Hybrid Barriers
        original_hybrid = papers_1_to_5_complete.HybridBarrierSynthesizer.synthesize_hybrid_barrier
        def traced_hybrid(self, *args, **kwargs):
            with TRACER.trace_paper(1, "Hybrid Barriers"):
                result = original_hybrid(self, *args, **kwargs)
                if result and result.is_safe:
                    TRACER.mark_fp_found(1)
                return result
        papers_1_to_5_complete.HybridBarrierSynthesizer.synthesize_hybrid_barrier = traced_hybrid
        
        # Paper #2: Stochastic Barriers (different from Paper #25)
        original_stoch = papers_1_to_5_complete.StochasticBarrierSynthesizer.synthesize_stochastic_barrier
        def traced_stoch(self, *args, **kwargs):
            with TRACER.trace_paper(2, "Stochastic Barriers (Paper #2)"):
                result = original_stoch(self, *args, **kwargs)
                if result[0]:  # is_safe
                    TRACER.mark_fp_found(2)
                return result
        papers_1_to_5_complete.StochasticBarrierSynthesizer.synthesize_stochastic_barrier = traced_stoch
        
        # Paper #3: SOS Safety
        original_sos = papers_1_to_5_complete.SOSSafetyVerifier.verify_safety_sos
        def traced_sos(self, *args, **kwargs):
            with TRACER.trace_paper(3, "SOS Safety"):
                result = original_sos(self, *args, **kwargs)
                if result[0]:  # is_safe
                    TRACER.mark_fp_found(3)
                return result
        papers_1_to_5_complete.SOSSafetyVerifier.verify_safety_sos = traced_sos
        
        # Paper #4: SOSTOOLS
        original_sostools = papers_1_to_5_complete.SOSTOOLSFramework.synthesize_barrier
        def traced_sostools(self, *args, **kwargs):
            with TRACER.trace_paper(4, "SOSTOOLS"):
                result = original_sostools(self, *args, **kwargs)
                if result[0]:  # is_safe
                    TRACER.mark_fp_found(4)
                return result
        papers_1_to_5_complete.SOSTOOLSFramework.synthesize_barrier = traced_sostools
        
        # Paper #5: Positivstellensatz
        original_pos = papers_1_to_5_complete.PositivstellensatzProver.prove_positivity
        def traced_pos(self, *args, **kwargs):
            with TRACER.trace_paper(5, "Positivstellensatz"):
                result = original_pos(self, *args, **kwargs)
                if result[0]:  # is_safe
                    TRACER.mark_fp_found(5)
                return result
        papers_1_to_5_complete.PositivstellensatzProver.prove_positivity = traced_pos
        
        print("✓ Tracing injected for Papers #1-5")
    except Exception as e:
        print(f"⚠ Could not trace Papers #1-5: {e}")
    
    # Patch Papers #6-10
    try:
        from pyfromscratch.barriers import papers_6_to_10_complete
        
        # Paper #6: Structured SOS
        original_paper6 = papers_6_to_10_complete.StructuredSOSDecomposer.decompose_and_verify
        def traced_paper6(self, *args, **kwargs):
            with TRACER.trace_paper(6, "Structured SOS"):
                result = original_paper6(self, *args, **kwargs)
                if result[0]:  # is_safe
                    TRACER.mark_fp_found(6)
                return result
        papers_6_to_10_complete.StructuredSOSDecomposer.decompose_and_verify = traced_paper6
        
        # Paper #7: Lasserre
        original_paper7 = papers_6_to_10_complete.LasserreHierarchySolver.solve_via_moments
        def traced_paper7(self, *args, **kwargs):
            with TRACER.trace_paper(7, "Lasserre"):
                result = original_paper7(self, *args, **kwargs)
                if result[0]:  # is_safe
                    TRACER.mark_fp_found(7)
                return result
        papers_6_to_10_complete.LasserreHierarchySolver.solve_via_moments = traced_paper7
        
        # Paper #8: Sparse SOS
        original_paper8 = papers_6_to_10_complete.SparseSOSVerifier.verify_using_sparsity
        def traced_paper8(self, *args, **kwargs):
            with TRACER.trace_paper(8, "Sparse SOS"):
                result = original_paper8(self, *args, **kwargs)
                if result[0]:  # is_safe
                    TRACER.mark_fp_found(8)
                return result
        papers_6_to_10_complete.SparseSOSVerifier.verify_using_sparsity = traced_paper8
        
        # Paper #9: DSOS/SDSOS
        original_paper9 = papers_6_to_10_complete.DSOSVerifier.verify_dsos
        def traced_paper9(self, *args, **kwargs):
            with TRACER.trace_paper(9, "DSOS/SDSOS"):
                result = original_paper9(self, *args, **kwargs)
                if result[0]:  # is_safe
                    TRACER.mark_fp_found(9)
                return result
        papers_6_to_10_complete.DSOSVerifier.verify_dsos = traced_paper9
        
        # Paper #10: IC3/PDR
        original_paper10 = papers_6_to_10_complete.IC3Verifier.verify_ic3
        def traced_paper10(self, *args, **kwargs):
            with TRACER.trace_paper(10, "IC3/PDR"):
                result = original_paper10(self, *args, **kwargs)
                if result[0]:  # is_safe
                    TRACER.mark_fp_found(10)
                return result
        papers_6_to_10_complete.IC3Verifier.verify_ic3 = traced_paper10
        
        print("✓ Tracing injected for Papers #6-10")
    except Exception as e:
        print(f"⚠ Could not trace Papers #6-10: {e}")
    
    # Patch Papers #11-15
    try:
        from pyfromscratch.barriers import papers_11_to_15_complete
        
        # Paper #11: IMC
        original_paper11 = papers_11_to_15_complete.IMCVerifier.verify_via_interpolation
        def traced_paper11(self, *args, **kwargs):
            with TRACER.trace_paper(11, "IMC"):
                result = original_paper11(self, *args, **kwargs)
                if result[0]:  # is_safe
                    TRACER.mark_fp_found(11)
                return result
        papers_11_to_15_complete.IMCVerifier.verify_via_interpolation = traced_paper11
        
        # Paper #12: CEGAR
        original_paper12 = papers_11_to_15_complete.CEGARVerifier.verify_with_cegar
        def traced_paper12(self, *args, **kwargs):
            with TRACER.trace_paper(12, "CEGAR"):
                result = original_paper12(self, *args, **kwargs)
                if result[0]:  # is_safe
                    TRACER.mark_fp_found(12)
                return result
        papers_11_to_15_complete.CEGARVerifier.verify_with_cegar = traced_paper12
        
        # Paper #13: Predicate Abstraction
        original_paper13 = papers_11_to_15_complete.PredicateAbstractionVerifier.verify_with_predicates
        def traced_paper13(self, *args, **kwargs):
            with TRACER.trace_paper(13, "Predicate Abstraction"):
                result = original_paper13(self, *args, **kwargs)
                if result[0]:  # is_safe
                    TRACER.mark_fp_found(13)
                return result
        papers_11_to_15_complete.PredicateAbstractionVerifier.verify_with_predicates = traced_paper13
        
        # Paper #14: Boolean Programs
        original_paper14 = papers_11_to_15_complete.BooleanProgramVerifier.verify_via_boolean_program
        def traced_paper14(self, *args, **kwargs):
            with TRACER.trace_paper(14, "Boolean Programs"):
                result = original_paper14(self, *args, **kwargs)
                if result[0]:  # is_safe
                    TRACER.mark_fp_found(14)
                return result
        papers_11_to_15_complete.BooleanProgramVerifier.verify_via_boolean_program = traced_paper14
        
        # Paper #15: IMPACT
        original_paper15 = papers_11_to_15_complete.IMPACTVerifier.verify_with_impact
        def traced_paper15(self, *args, **kwargs):
            with TRACER.trace_paper(15, "IMPACT"):
                result = original_paper15(self, *args, **kwargs)
                if result[0]:  # is_safe
                    TRACER.mark_fp_found(15)
                return result
        papers_11_to_15_complete.IMPACTVerifier.verify_with_impact = traced_paper15
        
        print("✓ Tracing injected for Papers #11-15")
    except Exception as e:
        print(f"⚠ Could not trace Papers #11-15: {e}")
    
    # Patch Papers #16-20
    try:
        from pyfromscratch.barriers import papers_16_to_20_complete
        
        # Paper #16: CHC Solving
        original_paper16 = papers_16_to_20_complete.CHCSolver.verify_via_chc
        def traced_paper16(self, *args, **kwargs):
            with TRACER.trace_paper(16, "CHC Solving"):
                result = original_paper16(self, *args, **kwargs)
                if result[0]:  # is_safe
                    TRACER.mark_fp_found(16)
                return result
        papers_16_to_20_complete.CHCSolver.verify_via_chc = traced_paper16
        
        # Paper #17: ICE Learning
        original_paper17 = papers_16_to_20_complete.ICELearner.verify_with_ice
        def traced_paper17(self, *args, **kwargs):
            with TRACER.trace_paper(17, "ICE Learning"):
                result = original_paper17(self, *args, **kwargs)
                if result[0]:  # is_safe
                    TRACER.mark_fp_found(17)
                return result
        papers_16_to_20_complete.ICELearner.verify_with_ice = traced_paper17
        
        # Paper #18: Houdini
        original_paper18 = papers_16_to_20_complete.HoudiniVerifier.verify_via_houdini
        def traced_paper18(self, *args, **kwargs):
            with TRACER.trace_paper(18, "Houdini"):
                result = original_paper18(self, *args, **kwargs)
                if result[0]:  # is_safe
                    TRACER.mark_fp_found(18)
                return result
        papers_16_to_20_complete.HoudiniVerifier.verify_via_houdini = traced_paper18
        
        # Paper #19: SyGuS
        original_paper19 = papers_16_to_20_complete.SyGuSSynthesizer.verify_via_sygus
        def traced_paper19(self, *args, **kwargs):
            with TRACER.trace_paper(19, "SyGuS"):
                result = original_paper19(self, *args, **kwargs)
                if result[0]:  # is_safe
                    TRACER.mark_fp_found(19)
                return result
        papers_16_to_20_complete.SyGuSSynthesizer.verify_via_sygus = traced_paper19
        
        # Paper #20: Assume-Guarantee
        original_paper20 = papers_16_to_20_complete.AssumeGuaranteeVerifier.verify_assume_guarantee
        def traced_paper20(self, *args, **kwargs):
            with TRACER.trace_paper(20, "Assume-Guarantee"):
                result = original_paper20(self, *args, **kwargs)
                if result[0]:  # is_safe
                    TRACER.mark_fp_found(20)
                return result
        papers_16_to_20_complete.AssumeGuaranteeVerifier.verify_assume_guarantee = traced_paper20
        
        print("✓ Tracing injected for Papers #16-20")
    except Exception as e:
        print(f"⚠ Could not trace Papers #16-20: {e}")
    
    # Patch synthesis engine (orchestrator for Papers #1-20)
    from pyfromscratch.barriers import synthesis_engine
    
    original_verify = synthesis_engine.UnifiedSynthesisEngine.verify
    def traced_verify(self, *args, **kwargs):
        # Determine which papers are being used based on problem type
        with TRACER.trace_paper(0, "Synthesis Engine (Papers 1-20)"):
            result = original_verify(self, *args, **kwargs)
            # This would trigger individual paper tracers
            return result
    synthesis_engine.UnifiedSynthesisEngine.verify = traced_verify
    
    print("✓ Tracing injected into all 25 papers")

def test_traced_pipeline():
    """Test the verification pipeline with tracing enabled."""
    
    print("="*80)
    print("TESTING ALL 25 PAPERS WITH CALL TRACING")
    print("="*80)
    print()
    
    # Inject tracing
    inject_tracing()
    
    # Load summaries
    print("Loading DeepSpeed summaries...")
    with open('results/deepspeed_crash_summaries.pkl', 'rb') as f:
        all_summaries = pickle.load(f)
    
    inference_funcs = {k: v for k, v in all_summaries.items()
                      if '.inference' in k.lower() or 'inference.' in k.lower()}
    
    print(f"Testing on {len(inference_funcs)} inference functions")
    print()
    
    # Create verifier
    from pyfromscratch.barriers.fast_barrier_filters import FastBarrierFilterPipeline
    from pyfromscratch.barriers.extreme_verification import ExtremeContextVerifier
    
    pipeline = FastBarrierFilterPipeline()
    pipeline.learn_from_codebase(inference_funcs)
    
    verifier = ExtremeContextVerifier()
    
    # Create test bugs
    print("Creating 50 test bugs...")
    bugs = []
    for func_name in list(inference_funcs.keys())[:25]:
        bugs.append({
            'function': func_name,
            'bug_type': 'DIV_ZERO',
            'bug_variable': 'param_0',
        })
        bugs.append({
            'function': func_name,
            'bug_type': 'NULL_PTR',
            'bug_variable': 'param_0',
        })
    
    print(f"Testing {len(bugs)} bugs...")
    print()
    
    # Test each bug
    print("Testing bugs...")
    print("-"*80)
    
    for i, bug in enumerate(bugs[:10]):  # Test first 10
        func_name = bug['function']
        bug_type = bug['bug_type']
        bug_variable = bug['bug_variable']
        
        summary = inference_funcs.get(func_name)
        if not summary:
            continue
        
        print(f"\nBug #{i+1}: {bug_type} on {bug_variable}")
        print(f"  Function: {func_name}")
        
        # Test full verification stack (not just Layer 0)
        try:
            result = verifier.verify_bug_extreme(
                bug_type=bug_type,
                bug_variable=bug_variable,
                crash_summary=summary,
                source_code=None,
                call_chain_summaries=[]
            )
            
            if result.is_safe:
                print(f"  ✓ Proven safe (full verification)")
            else:
                print(f"  ✗ Cannot prove safe")
        except Exception as e:
            print(f"  ✗ Verification failed: {e}")
    
    print()
    print("="*80)
    print("PAPER CALL STATISTICS")
    print("="*80)
    print()
    
    # Report statistics
    paper_names = {
        0: "Synthesis Engine (orchestrator)",
        21: "Likely Invariants (Paper #21)",
        22: "Separation Logic (Paper #22)",
        23: "Refinement Types (Paper #23)",
        24: "Interval Analysis (Paper #24)",
        25: "Stochastic Barriers (Paper #25)",
    }
    
    print(f"{'Paper':<40} {'Calls':>10} {'FPs':>10} {'Time (s)':>12}")
    print("-"*80)
    
    total_calls = 0
    total_fps = 0
    total_time = 0.0
    
    for paper_num in sorted(PAPER_CALLS.keys()):
        name = paper_names.get(paper_num, f"Paper #{paper_num}")
        calls = PAPER_CALLS[paper_num]
        fps = PAPER_FPS_FOUND[paper_num]
        time_s = PAPER_TIMES[paper_num]
        
        print(f"{name:<40} {calls:>10} {fps:>10} {time_s:>12.4f}")
        
        total_calls += calls
        total_fps += fps
        total_time += time_s
    
    print("-"*80)
    print(f"{'TOTAL':<40} {total_calls:>10} {total_fps:>10} {total_time:>12.4f}")
    print()
    
    # Analysis
    print("="*80)
    print("ANALYSIS")
    print("="*80)
    print()
    
    active_papers = [p for p in PAPER_CALLS.keys() if PAPER_CALLS[p] > 0]
    print(f"Papers called: {len(active_papers)}/25")
    print(f"Papers contributing FPs: {len([p for p in PAPER_FPS_FOUND.keys() if PAPER_FPS_FOUND[p] > 0])}")
    print()
    
    if len(active_papers) < 25:
        print("⚠ WARNING: Not all 25 papers are being called!")
        print()
        print("Missing papers:")
        for paper_num in range(1, 26):
            if paper_num not in active_papers:
                paper_range = {
                    (1, 4): "Papers #1-4: SOS/SDP Barrier Synthesis",
                    (5, 8): "Papers #5-8: CEGIS Certificate Synthesis",
                    (9, 11): "Papers #9-11: IC3/PDR, DSOS, IMC",
                    (12, 16): "Papers #12-16: CEGAR, Abstraction, IMPACT",
                    (17, 19): "Papers #17-19: ICE, Houdini, SyGuS",
                    (20, 20): "Paper #20: Assume-Guarantee",
                }
                for (start, end), desc in paper_range.items():
                    if start <= paper_num <= end:
                        print(f"  Paper #{paper_num}: {desc}")
                        break
    else:
        print("✓ All 25 papers are being called!")
    
    print()
    
    return active_papers, PAPER_FPS_FOUND

if __name__ == '__main__':
    try:
        active_papers, fps_by_paper = test_traced_pipeline()
        
        print("="*80)
        print("SUMMARY")
        print("="*80)
        print(f"Active papers: {len(active_papers)}/25")
        print(f"Papers finding FPs: {len([p for p in fps_by_paper if fps_by_paper[p] > 0])}")
        print()
        
        if len(active_papers) < 25:
            print("⚠ Need to implement and integrate missing papers!")
            sys.exit(1)
        else:
            print("✓ All papers integrated!")
            sys.exit(0)
        
    except Exception as e:
        print(f"ERROR: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
