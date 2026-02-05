#!/usr/bin/env python3
"""
Run full DeepSpeed analysis with detailed statistics on which phases/papers catch FPs.
"""
import sys
import time
import logging
import pickle
from pathlib import Path
from collections import defaultdict
from typing import Dict

from pyfromscratch.cfg.call_graph import build_call_graph_from_directory
from pyfromscratch.semantics.interprocedural_bugs import InterproceduralBugTracker
from pyfromscratch.semantics.crash_summaries import BytecodeCrashSummaryComputer

# Custom log handler to track verification statistics
class VerificationStatsHandler(logging.Handler):
    def __init__(self):
        super().__init__()
        self.stats = defaultdict(int)
        self.total_verified_safe = 0
        
    def emit(self, record):
        msg = record.getMessage()
        
        # Track Phase -2 (Quick Pre-Check)
        if '✓ [PHASE -2 QUICK PRE-CHECK]' in msg:
            self.stats['Phase -2: Quick Pre-Check'] += 1
            self.total_verified_safe += 1
        
        # Track Phase -1 (Bayesian)
        elif '✓ [PHASE -1 BAYESIAN]' in msg:
            self.stats['Phase -1: Bayesian FP Scorer'] += 1
            self.total_verified_safe += 1
        
        # Track Phase 0 (Semantic)
        elif '✓ [PHASE 0 SEMANTIC]' in msg:
            self.stats['Phase 0: Semantic Python'] += 1
            self.total_verified_safe += 1
        
        # Track Layer 0 papers
        elif '✓ [LAYER 0:' in msg:
            if 'LIKELY_INVARIANTS' in msg:
                self.stats['Layer 0: Paper #21 - Likely Invariants'] += 1
            elif 'SEPARATION_LOGIC' in msg:
                self.stats['Layer 0: Paper #22 - Separation Logic'] += 1
            elif 'REFINEMENT_TYPES' in msg:
                self.stats['Layer 0: Paper #23 - Refinement Types'] += 1
            elif 'INTERVAL_ANALYSIS' in msg:
                self.stats['Layer 0: Paper #24 - Interval Analysis'] += 1
            elif 'STOCHASTIC_BARRIERS' in msg:
                self.stats['Layer 0: Paper #25 - Stochastic Barriers'] += 1
            else:
                self.stats['Layer 0: Unknown Technique'] += 1
            self.total_verified_safe += 1
        
        # Track Layers 1-5
        elif '✓ [LAYER 1' in msg:
            self.stats['Layer 1: Papers #1-4 (SOS semantics)'] += 1
            self.total_verified_safe += 1
        elif '✓ [LAYER 2' in msg:
            self.stats['Layer 2: Papers #5-8 (CEGAR)'] += 1
            self.total_verified_safe += 1
        elif '✓ [LAYER 3' in msg:
            self.stats['Layer 3: Papers #9-12 (ICE learning)'] += 1
            self.total_verified_safe += 1
        elif '✓ [LAYER 4' in msg:
            self.stats['Layer 4: Papers #13-16 (IC3/PDR)'] += 1
            self.total_verified_safe += 1
        elif '✓ [LAYER 5' in msg:
            self.stats['Layer 5: Papers #17-20 (CHC solving)'] += 1
            self.total_verified_safe += 1

def main():
    print('='*80)
    print('DEEPSPEED FULL ANALYSIS WITH 25-PAPER VERIFICATION STATISTICS')
    print('='*80)
    print()
    
    deepspeed_dir = Path('external_tools/DeepSpeed/deepspeed')
    cache_file = Path('results/deepspeed_crash_summaries.pkl')
    
    if not deepspeed_dir.exists():
        print(f'ERROR: {deepspeed_dir} not found')
        return 1
    
    print(f'Analyzing: {deepspeed_dir}')
    print()
    
    # Set up logging with stats handler
    stats_handler = VerificationStatsHandler()
    stats_handler.setLevel(logging.WARNING)  # Capture ✓ lines
    
    root_logger = logging.getLogger()
    root_logger.addHandler(stats_handler)
    
    # Step 1: Build call graph
    print('[1/3] Building call graph...')
    t0 = time.time()
    call_graph = build_call_graph_from_directory(deepspeed_dir)
    t1 = time.time()
    print(f'  Functions: {len(call_graph.functions)}')
    print(f'  Time: {t1-t0:.1f}s')
    print()
    
    # Step 2: Compute crash summaries (with caching)
    if cache_file.exists():
        print('[2/3] Loading cached crash summaries...')
        t0 = time.time()
        with open(cache_file, 'rb') as f:
            crash_summaries = pickle.load(f)
        t1 = time.time()
        print(f'  Loaded {len(crash_summaries)} summaries from cache')
        print(f'  Time: {t1-t0:.1f}s')
    else:
        print('[2/3] Computing crash summaries (this may take several minutes)...')
        t0 = time.time()
        summary_computer = BytecodeCrashSummaryComputer(call_graph)
        crash_summaries = summary_computer.compute_all()
        t1 = time.time()
        print(f'  Summaries: {len(crash_summaries)}')
        print(f'  Time: {t1-t0:.1f}s ({t1-t0/60:.1f} minutes)')
        
        # Cache the results
        cache_file.parent.mkdir(exist_ok=True)
        print(f'  Saving to cache: {cache_file}')
        with open(cache_file, 'wb') as f:
            pickle.dump(crash_summaries, f)
    
    print()
    
    # Step 3: Find bugs with verification
    print('[3/3] Finding bugs with 25-paper verification...')
    print('(Watch for ✓ lines showing which phase/paper catches FPs)')
    print('-'*80)
    t0 = time.time()
    
    # Train Layer 0 fast barrier filters on the codebase
    from pyfromscratch.barriers.extreme_verification import get_extreme_verifier
    extreme_verifier = get_extreme_verifier()
    if hasattr(extreme_verifier, 'fast_filters'):
        print('  Training Layer 0 on codebase...')
        extreme_verifier.fast_filters.learn_from_codebase(crash_summaries)
        print('  Layer 0 trained!')
    print()
    
    tracker = InterproceduralBugTracker(
        crash_summaries=crash_summaries,
        call_graph=call_graph,
        entry_points=set(call_graph.functions.keys()),
        reachable_functions=set(call_graph.functions.keys()),
    )
    
    # Run the analysis
    all_bugs = tracker.find_all_bugs()
    
    # Group by type
    bugs_by_type = defaultdict(list)
    for bug in all_bugs:
        bugs_by_type[bug.bug_type].append(bug)
    
    t1 = time.time()
    print('-'*80)
    print()
    
    # Count bugs
    total_bugs = len(all_bugs)
    
    print('='*80)
    print('RESULTS')
    print('='*80)
    print()
    
    print(f'Total functions analyzed: {len(crash_summaries)}')
    print(f'Total bugs found (after verification): {total_bugs}')
    print(f'Total bugs verified as FPs: {stats_handler.total_verified_safe}')
    print(f'Analysis time: {t1-t0:.1f}s ({(t1-t0)/60:.1f} minutes)')
    print()
    
    print('-'*80)
    print('VERIFICATION STATISTICS BY PHASE/LAYER/PAPER')
    print('-'*80)
    print()
    
    # Sort by count (descending)
    sorted_stats = sorted(stats_handler.stats.items(), key=lambda x: x[1], reverse=True)
    
    if sorted_stats:
        # Calculate percentages
        for technique, count in sorted_stats:
            percentage = (count / stats_handler.total_verified_safe * 100) if stats_handler.total_verified_safe > 0 else 0
            print(f'{technique:50s}: {count:5d} FPs ({percentage:5.1f}%)')
    else:
        print('No verification statistics collected (verification may not have run)')
    
    print()
    print('-'*80)
    print('BUGS BY TYPE (after FP filtering)')
    print('-'*80)
    print()
    
    for bug_type, bugs in bugs_by_type.items():
        print(f'{bug_type:20s}: {len(bugs):4d}')
    
    print()
    print('='*80)
    print()
    
    # Show sample bugs
    if total_bugs > 0:
        print('Sample remaining bugs (first 5):')
        count = 0
        for bug_type, bugs in bugs_by_type.items():
            for bug in bugs:
                if count >= 5:
                    break
                print(f'  - {bug_type} in {bug.function_name}')
                count += 1
            if count >= 5:
                break
        print()
    
    # Summary of effectiveness
    print('='*80)
    print('ANALYSIS SUMMARY')
    print('='*80)
    print()
    
    if stats_handler.total_verified_safe > 0:
        # Calculate phase effectiveness
        phase_minus2 = stats_handler.stats.get('Phase -2: Quick Pre-Check', 0)
        phase_minus1 = stats_handler.stats.get('Phase -1: Bayesian FP Scorer', 0)
        phase_0 = stats_handler.stats.get('Phase 0: Semantic Python', 0)
        
        # Layer 0 total
        layer0_total = sum(
            stats_handler.stats.get(key, 0) 
            for key in stats_handler.stats.keys() 
            if key.startswith('Layer 0:')
        )
        
        # Layers 1-5 total
        deeper_layers = sum(
            stats_handler.stats.get(key, 0)
            for key in stats_handler.stats.keys()
            if key.startswith(('Layer 1:', 'Layer 2:', 'Layer 3:', 'Layer 4:', 'Layer 5:'))
        )
        
        print('Cheap phases (Phase -2, -1, 0):')
        print(f'  Caught {phase_minus2 + phase_minus1 + phase_0} FPs ({(phase_minus2 + phase_minus1 + phase_0)/stats_handler.total_verified_safe*100:.1f}%)')
        print(f'  - Phase -2 (instant): {phase_minus2} ({phase_minus2/stats_handler.total_verified_safe*100:.1f}%)')
        print(f'  - Phase -1 (Bayesian): {phase_minus1} ({phase_minus1/stats_handler.total_verified_safe*100:.1f}%)')
        print(f'  - Phase 0 (Semantic): {phase_0} ({phase_0/stats_handler.total_verified_safe*100:.1f}%)')
        print()
        
        print('Layer 0 (Papers #21-25, fast barriers):')
        print(f'  Caught {layer0_total} FPs ({layer0_total/stats_handler.total_verified_safe*100:.1f}%)')
        print()
        
        print('Layers 1-5 (Papers #1-20, expensive verification):')
        print(f'  Caught {deeper_layers} FPs ({deeper_layers/stats_handler.total_verified_safe*100:.1f}%)')
        print()
        
        # Speed estimate
        cheap_phases_pct = (phase_minus2 + phase_minus1 + phase_0) / stats_handler.total_verified_safe * 100
        print(f'Efficiency: {cheap_phases_pct:.1f}% of FPs caught by cheap phases')
        print(f'  → Estimated speedup vs. always running expensive layers: ~{1/(1-cheap_phases_pct/100):.1f}x')
    else:
        print('No FPs verified - all reported bugs passed verification as potential true positives')
    
    print()
    print('='*80)
    
    return 0

if __name__ == '__main__':
    sys.exit(main())
