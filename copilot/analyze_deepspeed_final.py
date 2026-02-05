#!/usr/bin/env python3
"""
Final improved analyzer with recommendations from manual code review.

New improvements:
1. Assert statement detection as guards
2. Immediate guard pattern recognition (if-check within 3 lines)
3. Config function confidence reduction
4. Init method defensive programming detection
"""

import ast
import json
import sys
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import List, Dict, Set, Optional
from collections import defaultdict
import time
import re

sys.path.insert(0, str(Path(__file__).parent))
from pyfromscratch.semantics.bytecode_summaries import analyze_code_object

# Configuration
NON_SECURITY_BUGS = ['BOUNDS', 'DIV_ZERO']
HIGH_CONFIDENCE_THRESHOLD = 0.8
MEDIUM_CONFIDENCE_THRESHOLD = 0.5

@dataclass
class BugReport:
    """Bug report with deduplication support."""
    type: str
    file: str
    function: str
    line: int
    confidence: float
    severity: str
    message: str
    full_path: str
    is_guarded: bool = False
    downgrade_reason: str = ""
    
    def key(self):
        """Unique key for deduplication."""
        return (self.file, self.function, self.line, self.type)

class FinalImprovedAnalyzer:
    """Final analyzer with all manual review recommendations implemented."""
    
    def __init__(self, project_path: str):
        self.project_path = Path(project_path)
        self.function_summaries = {}
        self.seen_bugs = set()
        self.stats = {
            'files_analyzed': 0,
            'functions_analyzed': 0,
            'bugs_total': 0,
            'bugs_deduplicated': 0,
            'bugs_downgraded': defaultdict(int),
        }
    
    def categorize_file(self, file_path: Path) -> str:
        """Categorize file type."""
        file_str = str(file_path).lower()
        
        if any(x in file_str for x in ['test', 'tests', 'testing', 'test_']):
            return 'test'
        if any(x in file_str for x in ['bench', 'benchmark', 'perf', 'profile']):
            return 'benchmark'
        if any(x in file_str for x in ['example', 'examples', 'demo', 'sample', 'tutorial']):
            return 'example'
        if 'setup.py' in file_str:
            return 'setup'
        
        return 'production'
    
    def check_assert_guards(self, source_lines: List[str], line_num: int, bug_type: str) -> bool:
        """
        NEW: Check if there are assert statements guarding this access.
        Recommendation #1 from manual review.
        """
        # Check previous 5 lines for assert statements
        start = max(0, line_num - 5)
        context = '\n'.join(source_lines[start:line_num])
        
        if bug_type == 'BOUNDS':
            # Check for assert len(...) > 0 or assert KEY in dict
            if 'assert len(' in context and '> 0' in context:
                return True
            if 'assert ' in context and ' in ' in context:
                # assert KEY in dict pattern
                return True
        
        elif bug_type == 'DIV_ZERO':
            # Check for assert denominator != 0 or > 0
            if 'assert ' in context and ('!= 0' in context or '> 0' in context):
                return True
        
        return False
    
    def check_immediate_guard(self, source_lines: List[str], line_num: int, bug_type: str) -> bool:
        """
        NEW: Check for immediate guard pattern (if-check within 3 lines of access).
        Recommendation #2 from manual review.
        
        Pattern: if KEY in dict: then dict[KEY] in same/next line = safe
        """
        # Check previous 3 lines
        start = max(0, line_num - 3)
        context_lines = source_lines[start:line_num]
        
        if bug_type == 'BOUNDS':
            # Look for "if KEY in dict.keys():" or "if KEY in dict:"
            for prev_line in context_lines:
                if 'if ' in prev_line and ' in ' in prev_line:
                    # Check if it's a dict membership check
                    if '.keys()' in prev_line or 'in config' in prev_line or 'in param' in prev_line:
                        return True
        
        return False
    
    def is_config_accessor(self, func_name: str, file_path: Path) -> bool:
        """
        NEW: Identify config accessor functions.
        Recommendation #3 from manual review.
        """
        func_lower = func_name.lower()
        file_str = str(file_path).lower()
        
        # Config accessor patterns
        if func_name.startswith('get_') and 'config' in file_str:
            return True
        if 'config' in func_lower and func_lower.startswith('get_'):
            return True
        
        return False
    
    def is_defensive_init(self, func_name: str, source_lines: List[str], lineno: int) -> bool:
        """
        NEW: Detect __init__ methods with defensive programming (multiple asserts).
        Recommendation #4 from manual review.
        """
        if func_name not in ['__init__', '__new__', '__post_init__']:
            return False
        
        # Check if function has multiple assert statements
        # Look at ~20 lines of the function
        end = min(len(source_lines), lineno + 20)
        func_body = '\n'.join(source_lines[lineno:end])
        
        assert_count = func_body.count('assert ')
        return assert_count >= 2
    
    def should_downgrade_severity(self, bug: BugReport, file_category: str, 
                                  source_lines: List[str], line_num: int,
                                  func_name: str, file_path: Path) -> tuple:
        """
        Enhanced downgrade logic with manual review recommendations.
        """
        reasons = []
        
        # Test/benchmark files
        if file_category in ['test', 'benchmark', 'example', 'setup']:
            reasons.append(f'{file_category}_file')
        
        # NEW: Check for assert guards (Recommendation #1)
        if self.check_assert_guards(source_lines, line_num, bug.type):
            reasons.append('assert_guard')
        
        # NEW: Check for immediate guard pattern (Recommendation #2)
        if self.check_immediate_guard(source_lines, line_num, bug.type):
            reasons.append('immediate_guard')
        
        # NEW: Config accessor heuristic (Recommendation #3)
        if self.is_config_accessor(func_name, file_path):
            reasons.append('config_accessor')
        
        # NEW: Defensive init detection (Recommendation #4)
        if self.is_defensive_init(func_name, source_lines, line_num):
            reasons.append('defensive_init')
        
        # Safe list comprehension patterns
        if line_num <= len(source_lines):
            source_line = source_lines[line_num - 1].strip()
            
            if '[' in source_line and 'for' in source_line:
                if 'range(len(' in source_line:
                    reasons.append('list_comp_range')
                elif 'enumerate(' in source_line:
                    reasons.append('list_comp_enumerate')
            
            # Iterator patterns
            if any(p in source_line for p in ['enumerate(', 'zip(', 'iter(', '.items(', '.values(', '.keys(']):
                reasons.append('iterator')
            
            # Loop counter divisions
            if bug.type == 'DIV_ZERO':
                if any(p in source_line for p in ['/ i', '/ idx', '/ count', '/ total', '/ num_', '/ n_']):
                    if not any(p in source_line for p in ['sum(', 'len(', 'count(']):
                        reasons.append('loop_counter_div')
        
        return len(reasons) > 0, ','.join(reasons)
    
    def analyze_function(self, func_name: str, func_code, file_path: Path, 
                        lineno: int, file_category: str) -> List[BugReport]:
        """Analyze function with enhanced filtering."""
        
        try:
            summary = analyze_code_object(
                func_code,
                func_name=func_name,
                callee_summaries=self.function_summaries
            )
        except Exception:
            return []
        
        # Store summary
        module_name = file_path.stem
        self.function_summaries[f"{module_name}.{func_name}"] = summary
        
        # Load source
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                source_lines = f.readlines()
        except:
            source_lines = []
        
        # Extract and filter bugs
        bugs = []
        for bug_finding in summary.potential_bugs:
            if bug_finding.bug_type not in NON_SECURITY_BUGS:
                continue
            
            self.stats['bugs_total'] += 1
            
            line_num = lineno
            
            # Create bug object
            bug = BugReport(
                type=bug_finding.bug_type,
                file=file_path.name,
                function=func_name,
                line=line_num,
                confidence=bug_finding.confidence,
                severity='',
                message=bug_finding.message,
                full_path=str(file_path),
                is_guarded=bug_finding.is_guarded
            )
            
            # Deduplicate
            bug_key = bug.key()
            if bug_key in self.seen_bugs:
                self.stats['bugs_deduplicated'] += 1
                continue
            self.seen_bugs.add(bug_key)
            
            # Determine base severity
            confidence = bug_finding.confidence
            is_guarded = bug_finding.is_guarded
            
            if is_guarded:
                severity = 'LOW'
                bug.downgrade_reason = 'guarded'
            elif confidence >= HIGH_CONFIDENCE_THRESHOLD:
                severity = 'HIGH'
            elif confidence >= MEDIUM_CONFIDENCE_THRESHOLD:
                severity = 'MEDIUM'
            else:
                severity = 'LOW'
                bug.downgrade_reason = 'low_confidence'
            
            # Enhanced downgrade check with new patterns
            if severity == 'HIGH':
                should_downgrade, reason = self.should_downgrade_severity(
                    bug, file_category, source_lines, line_num, func_name, file_path
                )
                
                if should_downgrade:
                    severity = 'MEDIUM' if 'assert_guard' in reason or 'immediate_guard' in reason else 'LOW'
                    bug.downgrade_reason = reason
                    self.stats['bugs_downgraded'][reason] += 1
            
            bug.severity = severity
            bugs.append(bug)
        
        return bugs
    
    def analyze_file(self, file_path: Path) -> Dict:
        """Analyze a single Python file."""
        
        file_category = self.categorize_file(file_path)
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                source = f.read()
        except:
            return {'file': file_path.name, 'error': 'read_failed', 'category': file_category}
        
        try:
            tree = ast.parse(source)
        except:
            return {'file': file_path.name, 'error': 'parse_failed', 'category': file_category}
        
        # Extract functions
        functions = []
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                functions.append({
                    'name': node.name,
                    'lineno': node.lineno,
                    'node': node
                })
        
        # Analyze each function
        all_bugs = []
        for func_info in functions:
            try:
                func_code = compile(
                    ast.Module(body=[func_info['node']], type_ignores=[]),
                    filename=str(file_path),
                    mode='exec'
                ).co_consts[0]
                
                bugs = self.analyze_function(
                    func_info['name'],
                    func_code,
                    file_path,
                    func_info['lineno'],
                    file_category
                )
                
                all_bugs.extend(bugs)
                self.stats['functions_analyzed'] += 1
                
            except:
                pass
        
        self.stats['files_analyzed'] += 1
        
        return {
            'file': file_path.name,
            'category': file_category,
            'functions': len(functions),
            'bugs': [asdict(b) for b in all_bugs]
        }
    
    def find_python_files(self) -> List[Path]:
        """Find all Python files."""
        files = []
        for py_file in self.project_path.rglob('*.py'):
            if '__pycache__' not in str(py_file):
                files.append(py_file)
        return sorted(files)
    
    def analyze_project(self) -> Dict:
        """Analyze entire project."""
        
        files = self.find_python_files()
        print(f"Found {len(files)} Python files to analyze")
        print()
        
        results = []
        start_time = time.time()
        
        report_interval = max(1, len(files) // 20)
        
        for i, file_path in enumerate(files):
            result = self.analyze_file(file_path)
            results.append(result)
            
            if (i + 1) % report_interval == 0 or i == len(files) - 1:
                elapsed = time.time() - start_time
                rate = (i + 1) / elapsed
                print(f"[{i+1}/{len(files)}] {file_path.name} ({rate:.1f} files/sec)")
        
        elapsed = time.time() - start_time
        
        return self.generate_report(results, elapsed)
    
    def generate_report(self, results: List[Dict], elapsed: float) -> Dict:
        """Generate comprehensive report."""
        
        all_bugs = []
        file_categories = defaultdict(int)
        
        for result in results:
            cat = result.get('category', 'unknown')
            file_categories[cat] += 1
            
            if 'bugs' in result:
                all_bugs.extend(result['bugs'])
        
        # Categorize bugs
        high_severity = [b for b in all_bugs if b['severity'] == 'HIGH']
        medium_severity = [b for b in all_bugs if b['severity'] == 'MEDIUM']
        low_severity = [b for b in all_bugs if b['severity'] == 'LOW']
        
        bugs_by_type = defaultdict(int)
        for bug in all_bugs:
            bugs_by_type[bug['type']] += 1
        
        bugs_by_file = defaultdict(list)
        for bug in high_severity:
            bugs_by_file[bug['file']].append(bug)
        
        top_files = sorted(bugs_by_file.items(), key=lambda x: len(x[1]), reverse=True)[:20]
        
        return {
            'project_path': str(self.project_path),
            'analyzer_version': 'final_improved_v2',
            'improvements': [
                'Assert statement detection',
                'Immediate guard pattern (if KEY in dict: dict[KEY])',
                'Config accessor confidence reduction',
                'Defensive __init__ detection'
            ],
            'analysis_metadata': {
                'files_analyzed': self.stats['files_analyzed'],
                'functions_analyzed': self.stats['functions_analyzed'],
                'elapsed_seconds': round(elapsed, 2),
                'files_per_second': round(self.stats['files_analyzed'] / elapsed, 2),
                'file_categories': dict(file_categories),
                'filtering_stats': {
                    'bugs_total': self.stats['bugs_total'],
                    'bugs_deduplicated': self.stats['bugs_deduplicated'],
                    'bugs_downgraded': dict(self.stats['bugs_downgraded'])
                }
            },
            'summary': {
                'total_bugs': len(all_bugs),
                'high_severity': len(high_severity),
                'medium_severity': len(medium_severity),
                'low_severity': len(low_severity),
                'bugs_by_type': dict(bugs_by_type)
            },
            'high_severity_bugs': high_severity,
            'medium_severity_bugs': medium_severity[:100],
            'bugs_by_file': {
                file: {'count': len(bugs), 'bugs': bugs}
                for file, bugs in top_files
            }
        }
    
    def print_summary(self, report: Dict):
        """Print human-readable summary."""
        
        print("\n" + "="*80)
        print("FINAL IMPROVED ANALYZER RESULTS")
        print("="*80)
        print()
        
        print("New improvements from manual review:")
        for imp in report['improvements']:
            print(f"  ✓ {imp}")
        print()
        
        meta = report['analysis_metadata']
        summary = report['summary']
        filtering = meta['filtering_stats']
        
        print(f"Project: {report['project_path']}")
        print()
        
        print(f"Performance:")
        print(f"  Files:     {meta['files_analyzed']}")
        print(f"  Functions: {meta['functions_analyzed']}")
        print(f"  Time:      {meta['elapsed_seconds']}s ({meta['files_per_second']:.1f} files/sec)")
        print()
        
        print(f"Bug filtering:")
        print(f"  Total bugs found:  {filtering['bugs_total']}")
        print(f"  Deduplicated:      {filtering['bugs_deduplicated']}")
        print(f"  Unique bugs:       {filtering['bugs_total'] - filtering['bugs_deduplicated']}")
        print()
        
        if filtering['bugs_downgraded']:
            print(f"Downgrade reasons (NEW patterns highlighted):")
            for reason, count in sorted(filtering['bugs_downgraded'].items(), key=lambda x: -x[1]):
                marker = "★" if reason in ['assert_guard', 'immediate_guard', 'config_accessor', 'defensive_init'] else " "
                print(f"  {marker} {reason:30s}: {count:3d}")
            print()
        
        print("="*80)
        print("FINAL RESULTS")
        print("="*80)
        print()
        
        print(f"Total bugs:      {summary['total_bugs']}")
        print(f"  HIGH:          {summary['high_severity']}")
        print(f"  MEDIUM:        {summary['medium_severity']}")
        print(f"  LOW:           {summary['low_severity']}")
        print()
        
        print(f"By type:")
        for bug_type, count in sorted(summary['bugs_by_type'].items(), key=lambda x: -x[1]):
            print(f"  {bug_type:15s}: {count:4d}")
        print()
        
        # Show sample HIGH severity bugs
        high_bugs = report['high_severity_bugs']
        if high_bugs:
            print("="*80)
            print(f"HIGH SEVERITY BUGS ({len(high_bugs)} total)")
            print("="*80)
            print()
            for i, bug in enumerate(high_bugs[:15], 1):
                print(f"{i}. {bug['type']} in {bug['file']}:{bug['function']}()")
                print(f"   Line {bug['line']}, confidence {bug['confidence']:.2f}")
                print()

def main():
    """Main entry point."""
    deepspeed_path = Path(__file__).parent / 'external_tools' / 'DeepSpeed'
    
    if not deepspeed_path.exists():
        print(f"Error: DeepSpeed not found at {deepspeed_path}")
        return 1
    
    print("="*80)
    print("FINAL IMPROVED ANALYZER - With Manual Review Recommendations")
    print("="*80)
    print()
    print("Implements 4 key recommendations:")
    print("  1. ✓ Assert statement detection as guards")
    print("  2. ✓ Immediate guard pattern recognition")
    print("  3. ✓ Config accessor confidence adjustment")
    print("  4. ✓ Defensive __init__ method detection")
    print()
    print(f"Target: {deepspeed_path}")
    print()
    
    analyzer = FinalImprovedAnalyzer(str(deepspeed_path))
    report = analyzer.analyze_project()
    
    # Save report
    output_file = Path(__file__).parent / 'results' / 'deepspeed_final_improved_analysis.json'
    output_file.parent.mkdir(exist_ok=True)
    
    with open(output_file, 'w') as f:
        json.dump(report, f, indent=2)
    
    print(f"\nReport saved to: {output_file}")
    
    # Print summary
    analyzer.print_summary(report)
    
    # Comparison
    print("\n" + "="*80)
    print("COMPARISON TO PREVIOUS VERSIONS")
    print("="*80)
    print()
    print("Original (no filtering):  16,049 bugs, 989 HIGH severity")
    print("Balanced filtering:        1,553 bugs,  31 HIGH severity")
    print(f"Final improved:            {report['summary']['total_bugs']:5d} bugs, {report['summary']['high_severity']:3d} HIGH severity")
    print()
    
    improvement = 31 - report['summary']['high_severity']
    if improvement > 0:
        pct = 100 * improvement / 31
        print(f"Further improvement: {improvement} fewer HIGH bugs ({pct:.1f}% reduction from balanced)")
        print(f"Total improvement: {989 - report['summary']['high_severity']} fewer HIGH bugs from original")
    
    return 0 if report['summary']['high_severity'] == 0 else 1

if __name__ == '__main__':
    sys.exit(main())
