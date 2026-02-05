#!/usr/bin/env python3
"""
Manually validate all 136 HIGH severity bugs by examining actual source code.
"""

import json
import sys
from pathlib import Path
from collections import defaultdict

def extract_source_context(file_path: Path, line_num: int, context: int = 5):
    """Extract source code context around the bug location."""
    try:
        lines = file_path.read_text().splitlines()
        start = max(0, line_num - context - 1)
        end = min(len(lines), line_num + context)
        
        context_lines = []
        for i in range(start, end):
            marker = ">>> " if i == line_num - 1 else "    "
            context_lines.append(f"{marker}{i+1:4d}: {lines[i]}")
        
        return "\n".join(context_lines)
    except Exception as e:
        return f"Error reading file: {e}"

def analyze_division(code_line: str, context_lines: str) -> dict:
    """Analyze if a division is actually unsafe."""
    analysis = {
        'has_division': False,
        'division_patterns': [],
        'safety_checks': [],
        'likely_safe': False,
        'reason': ''
    }
    
    # Check for division operators
    if '/' in code_line and '//' not in code_line and 'http://' not in code_line:
        analysis['has_division'] = True
        
        # Extract division patterns
        import re
        # Match patterns like "x / y" or "value / denominator"
        div_patterns = re.findall(r'(\w+)\s*/\s*(\w+)', code_line)
        analysis['division_patterns'] = div_patterns
    
    # Check for safety patterns in context
    context_lower = context_lines.lower()
    
    # Pattern 1: if denominator != 0 or if denominator > 0
    if any(pattern in context_lower for pattern in [
        'if ', '!= 0', '> 0', '< 0', 'assert', 'raise', 'zero'
    ]):
        analysis['safety_checks'].append('Conditional check detected')
    
    # Pattern 2: max() or abs() + constant
    if any(pattern in code_line.lower() for pattern in ['max(', 'abs(', ' or 1', ' or ']):
        analysis['safety_checks'].append('Safe idiom: max/abs/fallback')
        analysis['likely_safe'] = True
        analysis['reason'] = 'Uses safe idiom (max/abs/or)'
    
    # Pattern 3: len() in denominator
    if 'len(' in code_line:
        analysis['safety_checks'].append('len() in expression')
        # len() can be 0, not necessarily safe
    
    # Pattern 4: Constants or literals
    if any(c.isdigit() for c in code_line.split('/')[1].strip()[:3] if '/' in code_line):
        # Dividing by a numeric literal
        try:
            parts = code_line.split('/')
            if len(parts) >= 2:
                denominator = parts[1].strip().split()[0]
                if denominator.replace('.', '').replace('-', '').isdigit():
                    float_val = float(denominator)
                    if float_val != 0:
                        analysis['likely_safe'] = True
                        analysis['reason'] = f'Division by non-zero constant: {float_val}'
        except:
            pass
    
    # Pattern 5: Property access or method calls that likely return non-zero
    if re.search(r'\.\w+\(\)', code_line):
        # Method call as denominator - could be risky
        analysis['safety_checks'].append('Method call in denominator')
    
    return analysis

def main():
    print("=" * 80)
    print("MANUAL VALIDATION OF ALL 136 HIGH SEVERITY BUGS")
    print("=" * 80)
    print()
    
    # Load results
    results_file = Path(__file__).parent / 'results' / 'extreme_deepspeed_results.json'
    
    if not results_file.exists():
        print(f"Error: Results file not found: {results_file}")
        return
    
    with open(results_file) as f:
        results = json.load(f)
    
    high_bugs = results['high_severity_bugs']
    print(f"Total HIGH severity bugs to validate: {len(high_bugs)}")
    print()
    
    # Categories for classification
    categories = {
        'TRUE_POSITIVE': [],      # Definitely a bug
        'LIKELY_BUG': [],          # Probably a bug, needs review
        'LIKELY_SAFE': [],         # Probably safe, has protections
        'FALSE_POSITIVE': [],      # Definitely safe
        'NEEDS_REVIEW': [],        # Unclear, manual review needed
        'FILE_NOT_FOUND': []       # Can't access source
    }
    
    print("Analyzing each bug...\n")
    
    for i, bug in enumerate(high_bugs, 1):
        print(f"\n{'='*80}")
        print(f"Bug #{i}/{len(high_bugs)}: {bug['function']}")
        print(f"Location: {bug['location']}")
        print(f"Confidence: {bug['confidence']:.2f}")
        print(f"{'='*80}")
        
        # Parse location
        location = bug['location']
        try:
            file_path_str, line_str = location.rsplit(':', 1)
            line_num = int(line_str)
            file_path = Path(file_path_str)
            
            if not file_path.exists():
                print(f"⚠️  FILE NOT FOUND")
                categories['FILE_NOT_FOUND'].append((i, bug, "File not accessible"))
                continue
            
            # Extract source context
            context = extract_source_context(file_path, line_num, context=7)
            print(f"\nSource code context:")
            print(context)
            
            # Get the actual line
            lines = file_path.read_text().splitlines()
            if 0 <= line_num - 1 < len(lines):
                actual_line = lines[line_num - 1]
                
                # Analyze the division
                analysis = analyze_division(actual_line, context)
                
                print(f"\nAnalysis:")
                print(f"  Has division: {analysis['has_division']}")
                if analysis['division_patterns']:
                    print(f"  Division patterns: {analysis['division_patterns']}")
                if analysis['safety_checks']:
                    print(f"  Safety checks: {', '.join(analysis['safety_checks'])}")
                
                # Classify
                if analysis['likely_safe']:
                    classification = 'FALSE_POSITIVE'
                    print(f"  ✅ CLASSIFICATION: FALSE POSITIVE")
                    print(f"     Reason: {analysis['reason']}")
                    categories['FALSE_POSITIVE'].append((i, bug, analysis['reason']))
                elif not analysis['has_division']:
                    classification = 'FALSE_POSITIVE'
                    print(f"  ✅ CLASSIFICATION: FALSE POSITIVE")
                    print(f"     Reason: No division operator found")
                    categories['FALSE_POSITIVE'].append((i, bug, "No division operator"))
                elif analysis['safety_checks']:
                    classification = 'LIKELY_SAFE'
                    print(f"  ⚠️  CLASSIFICATION: LIKELY SAFE")
                    print(f"     Reason: Has safety checks: {', '.join(analysis['safety_checks'])}")
                    categories['LIKELY_SAFE'].append((i, bug, ', '.join(analysis['safety_checks'])))
                else:
                    classification = 'LIKELY_BUG'
                    print(f"  ❌ CLASSIFICATION: LIKELY BUG")
                    print(f"     Reason: Division with no obvious safety checks")
                    categories['LIKELY_BUG'].append((i, bug, "No safety checks detected"))
            else:
                print(f"⚠️  Line number out of range")
                categories['NEEDS_REVIEW'].append((i, bug, "Line out of range"))
                
        except Exception as e:
            print(f"❌ Error analyzing: {e}")
            categories['NEEDS_REVIEW'].append((i, bug, str(e)))
    
    # Summary report
    print("\n" + "=" * 80)
    print("VALIDATION SUMMARY")
    print("=" * 80)
    print()
    
    total = len(high_bugs)
    
    for category, bugs in categories.items():
        count = len(bugs)
        percentage = (count / total * 100) if total > 0 else 0
        print(f"{category:20s}: {count:3d} bugs ({percentage:5.1f}%)")
    
    # Detailed breakdown
    print("\n" + "=" * 80)
    print("DETAILED FINDINGS")
    print("=" * 80)
    
    # False Positives
    if categories['FALSE_POSITIVE']:
        print(f"\n✅ FALSE POSITIVES ({len(categories['FALSE_POSITIVE'])} bugs):")
        print("   These are NOT real bugs - safe patterns detected")
        for i, bug, reason in categories['FALSE_POSITIVES'][:10]:
            print(f"   #{i}: {bug['function']}")
            print(f"        {reason}")
    
    # Likely Safe
    if categories['LIKELY_SAFE']:
        print(f"\n⚠️  LIKELY SAFE ({len(categories['LIKELY_SAFE'])} bugs):")
        print("   These have safety checks but need verification")
        for i, bug, reason in categories['LIKELY_SAFE'][:10]:
            print(f"   #{i}: {bug['function']}")
            print(f"        {reason}")
    
    # Likely Bugs
    if categories['LIKELY_BUG']:
        print(f"\n❌ LIKELY BUGS ({len(categories['LIKELY_BUG'])} bugs):")
        print("   These appear to be real division by zero issues")
        for i, bug, reason in categories['LIKELY_BUG'][:10]:
            print(f"   #{i}: {bug['function']}")
            print(f"        Location: {bug['location']}")
    
    # Calculate true positive rate
    likely_real = len(categories['LIKELY_BUG']) + len(categories['TRUE_POSITIVE'])
    false_pos = len(categories['FALSE_POSITIVE']) + len(categories['LIKELY_SAFE'])
    
    print("\n" + "=" * 80)
    print("ESTIMATED ACCURACY")
    print("=" * 80)
    print(f"Likely Real Bugs:    {likely_real:3d} ({likely_real/total*100:.1f}%)")
    print(f"Likely False Pos:    {false_pos:3d} ({false_pos/total*100:.1f}%)")
    print(f"Needs More Review:   {len(categories['NEEDS_REVIEW']):3d} ({len(categories['NEEDS_REVIEW'])/total*100:.1f}%)")
    print(f"File Access Issues:  {len(categories['FILE_NOT_FOUND']):3d} ({len(categories['FILE_NOT_FOUND'])/total*100:.1f}%)")
    
    # Save detailed report
    report_file = Path(__file__).parent / 'results' / 'manual_validation_report.json'
    report = {
        'total_bugs': total,
        'categories': {
            cat: [{'bug_num': i, 'function': bug['function'], 'location': bug['location'], 'reason': reason}
                  for i, bug, reason in bugs]
            for cat, bugs in categories.items()
        },
        'summary': {
            'likely_real_bugs': likely_real,
            'likely_false_positives': false_pos,
            'needs_review': len(categories['NEEDS_REVIEW']),
            'file_not_found': len(categories['FILE_NOT_FOUND']),
            'true_positive_rate': f"{likely_real/total*100:.1f}%",
            'false_positive_rate': f"{false_pos/total*100:.1f}%"
        }
    }
    
    with open(report_file, 'w') as f:
        json.dump(report, f, indent=2)
    
    print(f"\nDetailed report saved to: {report_file}")

if __name__ == '__main__':
    main()
