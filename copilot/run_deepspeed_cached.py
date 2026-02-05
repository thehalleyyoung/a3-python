#!/usr/bin/env python3
"""
Run full DeepSpeed analysis with caching and comprehensive statistics.
"""
import sys
import time
import logging
import pickle
from pathlib import Path
from collections import defaultdict

from pyfromscratch.cfg.call_graph import build_call_graph_from_directory
from pyfromscratch.semantics.interprocedural_bugs import InterproceduralBugTracker
from pyfromscratch.semantics.crash_summaries import BytecodeCrashSummaryComputer

# Custom log handler to track verification statistics
class VerificationStatsHandler(logging.Handler):
    def __init__(self):
        super().__init__()
        self.stats = defaultdict(int)
        self.total_verified_safe = 0
        self.bug_examples = defaultdict(list)  # Store examples for each technique
        
    def emit(self, record):
        msg = record.getMessage()
        
        # Extract bug info if present
        bug_info = ""
        if " | " in msg:
            parts = msg.split(" | ")
            if len(parts) >= 2:
                bug_info = parts[1]  # e.g., "NULL_PTR on param_0"
        
        # Track Phase -2 (Quick Pre-Check)
        if '✓ [PHASE -2 QUICK PRE-CHECK]' in msg:
            technique = 'Phase -2: Quick Pre-Check'
            self.stats[technique] += 1
            self.total_verified_safe += 1
            if len(self.bug_examples[technique]) < 3:
                self.bug_examples[technique].append(bug_info)
        
        # Track Phase -1 (Bayesian)
        elif '✓ [PHASE -1 BAYESIAN]' in msg:
            technique = 'Phase -1: Bayesian FP Scorer'
            self.stats[technique] += 1
            self.total_verified_safe += 1
            if len(self.bug_examples[technique]) < 3:
                self.bug_examples[technique].append(bug_info)
        
        # Track Phase 0 (Semantic)
        elif '✓ [PHASE 0 SEMANTIC]' in msg:
            technique = 'Phase 0: Semantic Python'
            self.stats[technique] += 1
            self.total_verified_safe += 1
            if len(self.bug_examples[technique]) < 3:
                self.bug_examples[technique].append(bug_info)
        
        # Track Layer 0 papers
        elif '✓ [LAYER 0:' in msg:
            if 'LIKELY_INVARIANTS' in msg:
                technique = 'Layer 0: Paper #21 - Likely Invariants'
            elif 'SEPARATION_LOGIC' in msg:
                technique = 'Layer 0: Paper #22 - Separation Logic'
            elif 'REFINEMENT_TYPES' in msg:
                technique = 'Layer 0: Paper #23 - Refinement Types'
            elif 'INTERVAL_ANALYSIS' in msg:
                technique = 'Layer 0: Paper #24 - Interval Analysis'
            elif 'STOCHASTIC_BARRIERS' in msg:
                technique = 'Layer 0: Paper #25 - Stochastic Barriers'
            else:
                technique = 'Layer 0: Unknown Technique'
            
            self.stats[technique] += 1
            self.total_verified_safe += 1
            if len(self.bug_examples[technique]) < 3:
                self.bug_examples[technique].append(bug_info)
        
        # Track Layers 1-5
        elif '✓ [LAYER 1' in msg:
            technique = 'Layer 1: Papers #1-4 (SOS semantics)'
            self.stats[technique] += 1
            self.total_verified_safe += 1
        elif '✓ [LAYER 2' in msg:
            technique = 'Layer 2: Papers #5-8 (CEGAR)'
            self.stats[technique] += 1
            self.total_verified_safe += 1
        elif '✓ [LAYER 3' in msg:
            technique = 'Layer 3: Papers #9-12 (ICE learning)'
            self.stats[technique] += 1
            self.total_verified_safe += 1
        elif '✓ [LAYER 4' in msg:
            technique = 'Layer 4: Papers #13-16 (IC3/PDR)'
            self.stats[technique] += 1
            self.total_verified_safe += 1
        elif '✓ [LAYER 5' in msg:
            technique = 'Layer 5: Papers #17-20 (CHC solving)'
            self.stats[technique] += 1
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
        
        # Add progress reporting
        print(f'  Processing {len(call_graph.functions)} functions...')
        crash_summaries = summary_computer.compute_all()
        
        t1 = time.time()
        print(f'  Summaries: {len(crash_summaries)}')
        print(f'  Time: {t1-t0:.1f}s ({t1-t0:.1f} minutes)')
        
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
    
    tracker = InterproceduralBugTracker(
        crash_summaries=crash_summaries,
        call_graph=call_graph,
        skip_verification=False  # Enable verification
    )
    
    # Run the analysis
    bugs_by_type = tracker.get_all_bugs()
    
    t1 = time.time()
    print('-'*80)
    print()
    
    # Count bugs
    total_bugs = sum(len(bugs) for bugs in bugs_by_type.values())
    
    print('='*80)
    print('RESULTS')
    print('='*80)
    print()
    
    print(f'Total functions analyzed: {len(crash_summaries)}')
    print(f'Total bugs found (after verification): {total_bugs}')
    print(f'Total bugs verified as FPs: {stats_handler.total_verified_safe}')
    print(f'Bug analysis time: {t1-t0:.1f}s ({(t1-t0)/60:.1f} minutes)')
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
            
            # Show examples
            if technique in stats_handler.bug_examples and stats_handler.bug_examples[technique]:
                examples = stats_handler.bug_examples[technique][:2]
                for ex in examples:
                    if ex:
                        print(f'  Example: {ex}')
    else:
        print('No verification statistics collected')
    
    print()
    print('-'*80)
    print('BUGS BY TYPE (after FP filtering)')
    print('-'*80)
    print()
    
    for bug_type, bugs in sorted(bugs_by_type.items(), key=lambda x: len(x[1]), reverse=True):
        print(f'{bug_type:20s}: {len(bugs):4d}')
    
    print()
    print('='*80)
    
    # Show sample bugs
    if total_bugs > 0:
        print('Sample remaining bugs (first 10):')
        count = 0
        for bug_type, bugs in bugs_by_type.items():
            for bug in bugs:
                if count >= 10:
                    break
                print(f'  - {bug_type} in {bug.function_name}')
                if hasattr(bug, 'variable') and bug.variable:
                    print(f'      variable: {bug.variable}')
                count += 1
            if count >= 10:
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
        
        cheap_total = phase_minus2 + phase_minus1 + phase_0
        
        print('Cheap phases (Phase -2, -1, 0) - O(1) to O(n):')
        print(f'  Caught {cheap_total} FPs ({cheap_total/stats_handler.total_verified_safe*100:.1f}%)')
        print(f'  - Phase -2 (instant pre-check): {phase_minus2:4d} ({phase_minus2/stats_handler.total_verified_safe*100:5.1f}%)')
        print(f'  - Phase -1 (Bayesian scorer):   {phase_minus1:4d} ({phase_minus1/stats_handler.total_verified_safe*100:5.1f}%)')
        print(f'  - Phase 0 (Semantic Python):    {phase_0:4d} ({phase_0/stats_handler.total_verified_safe*100:5.1f}%)')
        print()
        
        print('Layer 0 (Papers #21-25, fast barriers) - O(n):')
        print(f'  Caught {layer0_total} FPs ({layer0_total/stats_handler.total_verified_safe*100:.1f}%)')
        for key in sorted(stats_handler.stats.keys()):
            if key.startswith('Layer 0:'):
                count = stats_handler.stats[key]
                print(f'  - {key}: {count}')
        print()
        
        print('Layers 1-5 (Papers #1-20, expensive verification) - O(n²) to O(n³):')
        print(f'  Caught {deeper_layers} FPs ({deeper_layers/stats_handler.total_verified_safe*100:.1f}%)')
        print()
        
        # Speed estimate
        cheap_phases_pct = cheap_total / stats_handler.total_verified_safe * 100
        print(f'⚡ Efficiency: {cheap_phases_pct:.1f}% of FPs caught by cheap phases')
        print(f'  → These run in O(1) to O(n) time vs O(n²)+ for deep verification')
        
        if cheap_phases_pct > 0:
            # Rough estimate: cheap phases take 0.001s, expensive take 0.1s
            time_without_opt = stats_handler.total_verified_safe * 0.1
            time_with_opt = (cheap_total * 0.001) + (deeper_layers * 0.1)
            speedup = time_without_opt / time_with_opt if time_with_opt > 0 else 1.0
            print(f'  → Estimated speedup: ~{speedup:.1f}x faster than always running deep layers')
    else:
        print('No FPs verified - all reported bugs appear to be potential true positives')
    
    print()
    print('='*80)
    
    return 0

if __name__ == '__main__':
    sys.exit(main())
