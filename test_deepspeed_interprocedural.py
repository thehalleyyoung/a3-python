#!/usr/bin/env python3
"""Test enhanced interprocedural bounds analysis on DeepSpeed."""

import sys
import os
from pathlib import Path
from collections import defaultdict

# Add parent to path
sys.path.insert(0, str(Path(__file__).parent))

from pyfromscratch.analyzer import analyze_file

DEEPSPEED_PATH = Path(__file__).parent / "external_tools" / "DeepSpeed"

def analyze_deepspeed_files():
    """Analyze DeepSpeed Python files with enhanced interprocedural analysis."""
    
    if not DEEPSPEED_PATH.exists():
        print(f"❌ DeepSpeed not found at {DEEPSPEED_PATH}")
        return
    
    print("=" * 80)
    print("TESTING ENHANCED INTERPROCEDURAL ANALYSIS ON DEEPSPEED")
    print("=" * 80)
    
    # Focus on files that likely have bounds/div issues
    target_files = [
        "deepspeed/checkpoint/ds_to_universal.py",  # The sum(slices)/len(slices) bug at line 287
        "deepspeed/runtime/zero/partition_parameters.py",
        "deepspeed/runtime/zero/partitioned_param_coordinator.py",
        "deepspeed/utils/numa.py",
        "deepspeed/monitor/monitor.py",
    ]
    
    all_bugs = []
    files_with_bugs = defaultdict(list)
    
    for rel_path in target_files:
        file_path = DEEPSPEED_PATH / rel_path
        if not file_path.exists():
            print(f"⚠️  File not found: {rel_path}")
            continue
        
        print(f"\n{'=' * 80}")
        print(f"Analyzing: {rel_path}")
        print(f"{'=' * 80}")
        
        try:
            # Read the file
            with open(file_path, 'r', encoding='utf-8') as f:
                source_code = f.read()
            
            result = analyze_file(str(file_path), source_code)
            
            if not result or not result.bugs:
                print(f"  ✅ No bugs detected")
                continue
            
            bugs = result.bugs
            
            # Convert to dict format for easier handling
            bugs_dict = []
            for bug in bugs:
                # Extract line number from location (format: "file.py:line")
                line_num = 0
                if bug.location and ':' in bug.location:
                    try:
                        line_num = int(bug.location.split(':')[1])
                    except:
                        pass
                
                bugs_dict.append({
                    'bug_type': bug.bug_type,
                    'line': line_num,
                    'confidence': 0.5,  # Default confidence since not in BugFinding
                    'is_guarded': False,  # Not available in this structure
                    'context': bug.message
                })
            
            # Separate by bug type
            bounds_bugs = [b for b in bugs_dict if b['bug_type'] == 'BOUNDS']
            div_bugs = [b for b in bugs_dict if b['bug_type'] == 'DIV_ZERO']
            other_bugs = [b for b in bugs_dict if b['bug_type'] not in ['BOUNDS', 'DIV_ZERO']]
            
            if bounds_bugs:
                print(f"\n  🔍 BOUNDS bugs: {len(bounds_bugs)}")
                for bug in sorted(bounds_bugs, key=lambda x: -x['confidence'])[:5]:
                    line = bug['line']
                    conf = bug['confidence']
                    guarded = bug['is_guarded']
                    guard_str = " [GUARDED]" if guarded else ""
                    print(f"    Line {line}: confidence={conf:.2f}{guard_str}")
                if len(bounds_bugs) > 5:
                    print(f"    ... and {len(bounds_bugs) - 5} more")
            
            if div_bugs:
                print(f"\n  ⚠️  DIV_ZERO bugs: {len(div_bugs)}")
                for bug in sorted(div_bugs, key=lambda x: -x['confidence'])[:5]:
                    line = bug['line']
                    conf = bug['confidence']
                    guarded = bug['is_guarded']
                    guard_str = " [GUARDED]" if guarded else ""
                    print(f"    Line {line}: confidence={conf:.2f}{guard_str}")
                    if 'len(' in bug['context']:
                        print(f"      Context: len() division detected")
                if len(div_bugs) > 5:
                    print(f"    ... and {len(div_bugs) - 5} more")
            
            if other_bugs:
                print(f"\n  📋 Other bugs: {len(other_bugs)}")
                bug_types = defaultdict(int)
                for bug in other_bugs:
                    bug_types[bug['bug_type']] += 1
                for bug_type, count in bug_types.items():
                    print(f"    {bug_type}: {count}")
            
            all_bugs.extend(bugs_dict)
            files_with_bugs[rel_path] = bugs_dict
            
        except Exception as e:
            print(f"  ❌ Error analyzing: {e}")
            import traceback
            traceback.print_exc()
    
    # Summary
    print(f"\n{'=' * 80}")
    print("SUMMARY")
    print(f"{'=' * 80}")
    print(f"Files analyzed: {len(target_files)}")
    print(f"Files with bugs: {len(files_with_bugs)}")
    print(f"Total bugs found: {len(all_bugs)}")
    
    if all_bugs:
        print(f"\nBug breakdown:")
        bug_type_counts = defaultdict(int)
        for bug in all_bugs:
            bug_type_counts[bug['bug_type']] += 1
        
        for bug_type in sorted(bug_type_counts.keys()):
            count = bug_type_counts[bug_type]
            print(f"  {bug_type}: {count}")
        
        # High confidence non-security bugs
        high_conf_bounds = [b for b in all_bugs if b['bug_type'] == 'BOUNDS' and b['confidence'] >= 0.8]
        high_conf_div = [b for b in all_bugs if b['bug_type'] == 'DIV_ZERO' and b['confidence'] >= 0.8]
        
        print(f"\n🎯 High-confidence (≥0.8) non-security bugs:")
        print(f"  BOUNDS: {len(high_conf_bounds)}")
        print(f"  DIV_ZERO: {len(high_conf_div)}")
        
        if high_conf_bounds or high_conf_div:
            print(f"\n📍 Notable findings:")
            for bug in (high_conf_bounds + high_conf_div)[:10]:
                file_name = Path([k for k, v in files_with_bugs.items() if bug in v][0]).name
                print(f"  {bug['bug_type']} in {file_name}:{bug['line']} (conf={bug['confidence']:.2f})")


def test_specific_pattern():
    """Test the specific sum(slices)/len(slices) pattern."""
    print(f"\n{'=' * 80}")
    print("TESTING SPECIFIC PATTERN: sum(slices) / len(slices)")
    print(f"{'=' * 80}")
    
    target_file = DEEPSPEED_PATH / "deepspeed/checkpoint/ds_to_universal.py"
    
    if not target_file.exists():
        print(f"❌ File not found: {target_file}")
        return
    
    print(f"Analyzing: {target_file.name}")
    
    try:
        # Read the file to find the specific pattern
        with open(target_file, 'r') as f:
            lines = f.readlines()
        
        pattern_line = None
        for i, line in enumerate(lines, 1):
            if 'sum(slices)' in line and 'len(slices)' in line:
                pattern_line = i
                print(f"\n✓ Found pattern at line {i}:")
                print(f"  {line.strip()}")
                break
        
        if not pattern_line:
            print("⚠️  Pattern not found in file")
            return
        
        # Analyze the file
        with open(target_file, 'r', encoding='utf-8') as f:
            source_code = f.read()
        
        result = analyze_file(str(target_file), source_code)
        
        if not result or not result.bugs:
            print(f"\n⚠️  No bugs detected in file")
            return
        
        # Convert bugs to dict format
        bugs_dict = []
        for bug in result.bugs:
            # Extract line number from location
            line_num = 0
            if bug.location and ':' in bug.location:
                try:
                    line_num = int(bug.location.split(':')[1])
                except:
                    pass
            
            bugs_dict.append({
                'bug_type': bug.bug_type,
                'line': line_num,
                'confidence': 0.5,
                'is_guarded': False,
            })
        
        # Look for DIV_ZERO near that line
        div_bugs = [b for b in bugs_dict if b['bug_type'] == 'DIV_ZERO']
        
        print(f"\n📊 DIV_ZERO bugs found: {len(div_bugs)}")
        
        # Find bugs near the pattern line
        nearby_bugs = [b for b in div_bugs if abs(b['line'] - pattern_line) <= 5]
        
        if nearby_bugs:
            print(f"\n🎯 DIV_ZERO bug(s) near the pattern:")
            for bug in nearby_bugs:
                print(f"  Line {bug['line']}: confidence={bug['confidence']:.2f}")
                print(f"    Guarded: {bug['is_guarded']}")
                print(f"    ✅ Our enhanced analysis detected this potential issue!")
        else:
            print(f"\n⚠️  No DIV_ZERO bugs detected near line {pattern_line}")
            print(f"    This could mean:")
            print(f"      1. The function has guards we're not detecting")
            print(f"      2. The pattern is in a context we're not analyzing")
            print(f"      3. Need to check if we're analyzing the right function")
        
        # Show all DIV_ZERO bugs for context
        if div_bugs:
            print(f"\n📋 All DIV_ZERO bugs in file:")
            for bug in sorted(div_bugs, key=lambda x: x['line']):
                print(f"  Line {bug['line']}: confidence={bug['confidence']:.2f}")
        
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == '__main__':
    analyze_deepspeed_files()
    test_specific_pattern()
    
    print(f"\n{'=' * 80}")
    print("✅ DeepSpeed analysis complete!")
    print(f"{'=' * 80}")
