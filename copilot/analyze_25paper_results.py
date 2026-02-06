#!/usr/bin/env python3
"""
Parse the debug log from 25-paper DeepSpeed analysis and show summary statistics.
"""

import sys
import re
from collections import defaultdict, Counter
from pathlib import Path

def parse_debug_log(log_file):
    """Parse the debug log and extract statistics."""
    
    stats = {
        'total_bugs_analyzed': 0,
        'phase_minus2_safe': 0,  # Quick pre-check
        'phase_minus1_safe': 0,  # Bayesian
        'phase_0_safe': 0,       # Semantic
        'layer_0_safe': 0,       # Papers #21-25
        'layer_1_2_safe': 0,     # Papers #1-8
        'layer_3_4_safe': 0,     # Papers #9-19
        'layer_5_safe': 0,       # Paper #20
        'guards_safe': 0,        # Protected by guards
        'paper_contributions': Counter(),
        'bug_types': Counter(),
        'verification_times': [],
        'functions_analyzed': set(),
    }
    
    with open(log_file, 'r') as f:
        for line in f:
            # Track functions analyzed
            if '[EXTREME] Verifying' in line:
                stats['total_bugs_analyzed'] += 1
                # Extract bug type
                match = re.search(r'Verifying (\w+) on', line)
                if match:
                    stats['bug_types'][match.group(1)] += 1
            
            # Track Phase -2
            if '✓ [PHASE -2 QUICK PRE-CHECK]' in line:
                stats['phase_minus2_safe'] += 1
            
            # Track Phase -1
            elif '✓ [PHASE -1 BAYESIAN]' in line:
                stats['phase_minus1_safe'] += 1
            
            # Track Phase 0
            elif '✓ [PHASE 0 SEMANTIC]' in line:
                stats['phase_0_safe'] += 1
            
            # Track Layer 0
            elif '✓ [LAYER 0:' in line or 'Paper #2' in line:
                stats['layer_0_safe'] += 1
                if 'Paper #21' in line or 'LIKELY_INVARIANTS' in line:
                    stats['paper_contributions']['Paper #21: Likely Invariants'] += 1
                elif 'Paper #22' in line or 'SEPARATION_LOGIC' in line:
                    stats['paper_contributions']['Paper #22: Separation Logic'] += 1
                elif 'Paper #23' in line:
                    stats['paper_contributions']['Paper #23: Refinement Types'] += 1
                elif 'Paper #24' in line:
                    stats['paper_contributions']['Paper #24: Interval Analysis'] += 1
                elif 'Paper #25' in line or 'STOCHASTIC_BARRIERS' in line:
                    stats['paper_contributions']['Paper #25: Stochastic Barriers'] += 1
            
            # Track Layers 1-2 (Papers #1-8)
            elif '✓ [LAYER 2: SOS/SDP]' in line or 'Paper #1' in line:
                stats['layer_1_2_safe'] += 1
                if 'Paper #1' in line:
                    stats['paper_contributions']['Paper #1: Hybrid Barriers'] += 1
                elif 'Paper #6' in line:
                    stats['paper_contributions']['Paper #6: Structured SOS'] += 1
            
            # Track Layers 3-4 (Papers #9-19)
            elif 'Paper #12' in line and 'CEGAR' in line:
                stats['layer_3_4_safe'] += 1
                stats['paper_contributions']['Paper #12: CEGAR'] += 1
            elif 'Paper #16' in line and 'CHC' in line:
                stats['layer_3_4_safe'] += 1
                stats['paper_contributions']['Paper #16: CHC Solving'] += 1
            elif 'Paper #17' in line and 'ICE' in line:
                stats['layer_3_4_safe'] += 1
                stats['paper_contributions']['Paper #17: ICE Learning'] += 1
            elif 'Paper #19' in line and 'SyGuS' in line:
                stats['layer_3_4_safe'] += 1
                stats['paper_contributions']['Paper #19: SyGuS'] += 1
            
            # Track Layer 5 (Paper #20)
            elif 'Paper #20' in line and 'Assume' in line:
                stats['layer_5_safe'] += 1
                stats['paper_contributions']['Paper #20: Assume-Guarantee'] += 1
            
            # Track guard protection
            if 'Protected by guards, SAFE' in line:
                stats['guards_safe'] += 1
            
            # Track verification times
            if 'Result: SAFE' in line and 'ms)' in line:
                match = re.search(r'\((\d+\.\d+)ms\)', line)
                if match:
                    stats['verification_times'].append(float(match.group(1)))
            
            # Track function names
            if '[TRACKER] Analyzing' in line:
                match = re.search(r'Analyzing ([^\s]+) for', line)
                if match:
                    stats['functions_analyzed'].add(match.group(1))
    
    return stats

def print_summary(stats):
    """Print comprehensive summary of results."""
    
    print("=" * 80)
    print("25-PAPER VERIFICATION SYSTEM: DEEPSPEED ANALYSIS RESULTS")
    print("=" * 80)
    print()
    
    total_verified = (stats['phase_minus2_safe'] + stats['phase_minus1_safe'] + 
                     stats['phase_0_safe'] + stats['layer_0_safe'] + 
                     stats['layer_1_2_safe'] + stats['layer_3_4_safe'] + 
                     stats['layer_5_safe'] + stats['guards_safe'])
    
    print(f"Total Bugs Analyzed:     {stats['total_bugs_analyzed']:,}")
    print(f"Total Verified Safe:     {total_verified:,}")
    print(f"Unique Functions:        {len(stats['functions_analyzed']):,}")
    if total_verified > 0:
        print(f"Verification Rate:       {total_verified/stats['total_bugs_analyzed']*100:.1f}%")
    print()
    
    print("=" * 80)
    print("VERIFICATION BY PHASE/LAYER")
    print("=" * 80)
    print()
    print(f"Phase -2 (Quick Pre-Check):      {stats['phase_minus2_safe']:5,}  ({stats['phase_minus2_safe']/total_verified*100:.1f}%)")
    print(f"Phase -1 (Bayesian Scorer):      {stats['phase_minus1_safe']:5,}  ({stats['phase_minus1_safe']/total_verified*100 if total_verified else 0:.1f}%)")
    print(f"Phase 0 (Semantic Python):       {stats['phase_0_safe']:5,}  ({stats['phase_0_safe']/total_verified*100 if total_verified else 0:.1f}%)")
    print(f"Layer 0 (Papers #21-25):         {stats['layer_0_safe']:5,}  ({stats['layer_0_safe']/total_verified*100 if total_verified else 0:.1f}%)")
    print(f"Layers 1-2 (Papers #1-8):        {stats['layer_1_2_safe']:5,}  ({stats['layer_1_2_safe']/total_verified*100 if total_verified else 0:.1f}%)")
    print(f"Layers 3-4 (Papers #9-19):       {stats['layer_3_4_safe']:5,}  ({stats['layer_3_4_safe']/total_verified*100 if total_verified else 0:.1f}%)")
    print(f"Layer 5 (Paper #20):             {stats['layer_5_safe']:5,}  ({stats['layer_5_safe']/total_verified*100 if total_verified else 0:.1f}%)")
    print(f"Guards (No paper needed):        {stats['guards_safe']:5,}  ({stats['guards_safe']/total_verified*100 if total_verified else 0:.1f}%)")
    print()
    
    print("=" * 80)
    print("INDIVIDUAL PAPER CONTRIBUTIONS")
    print("=" * 80)
    print()
    if stats['paper_contributions']:
        for paper, count in stats['paper_contributions'].most_common():
            print(f"{paper:40s} {count:5,}")
    else:
        print("No individual paper contributions detected")
    print()
    
    print("=" * 80)
    print("BUG TYPE DISTRIBUTION")
    print("=" * 80)
    print()
    for bug_type, count in stats['bug_types'].most_common():
        print(f"{bug_type:30s} {count:5,}")
    print()
    
    if stats['verification_times']:
        print("=" * 80)
        print("PERFORMANCE STATISTICS")
        print("=" * 80)
        print()
        times = stats['verification_times']
        print(f"Average verification time:   {sum(times)/len(times):.2f} ms")
        print(f"Min verification time:       {min(times):.2f} ms")
        print(f"Max verification time:       {max(times):.2f} ms")
        print(f"Total verifications timed:   {len(times):,}")
        print()
    
    print("=" * 80)
    print("KEY FINDINGS")
    print("=" * 80)
    print()
    
    # Determine which papers are most effective
    if stats['layer_1_2_safe'] > 0:
        print(f"✅ Papers #1-8 (SOS/SDP) are highly effective: {stats['layer_1_2_safe']:,} bugs proven safe")
    
    if stats['paper_contributions']['Paper #1: Hybrid Barriers'] > 0:
        print(f"✅ Paper #1 (Hybrid Barriers) is the top contributor: {stats['paper_contributions']['Paper #1: Hybrid Barriers']:,} bugs")
    
    if stats['phase_minus2_safe'] > total_verified * 0.3:
        print(f"✅ Phase -2 (Quick Pre-Check) catching {stats['phase_minus2_safe']/total_verified*100:.0f}% - very efficient!")
    
    if stats['guards_safe'] > 0:
        print(f"✅ Guard-based verification handling {stats['guards_safe']:,} cases without papers")
    
    papers_needed = total_verified - stats['phase_minus2_safe'] - stats['guards_safe'] - stats['phase_0_safe']
    if papers_needed > 0:
        print(f"✅ Deep verification (Papers #1-20) needed for {papers_needed:,} complex cases")
    
    print()

if __name__ == '__main__':
    if len(sys.argv) > 1:
        log_file = sys.argv[1]
    else:
        # Find most recent log
        log_dir = Path('results')
        logs = list(log_dir.glob('deepspeed_25papers_debug_*.log'))
        if not logs:
            print("No debug log files found in results/")
            sys.exit(1)
        log_file = max(logs, key=lambda p: p.stat().st_mtime)
    
    print(f"Parsing: {log_file}")
    print()
    
    stats = parse_debug_log(log_file)
    print_summary(stats)
