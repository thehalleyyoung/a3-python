#!/usr/bin/env python3
"""
Improved DeepSpeed analyzer - balanced filtering approach.

Key improvements over original:
1. Deduplicate bug reports
2. Filter obvious false positive patterns
3. Exclude test/benchmark files from HIGH severity (but still analyze)
4. Keep statistics on what was filtered
"""

import ast
import json
import sys
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import List, Dict, Set
from collections import defaultdict
import time

# Add pyfromscratch to path
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

class BalancedDeepSpeedAnalyzer:
    """Balanced analyzer with smart filtering."""
    
    def __init__(self, deepspeed_path: str):
        self.deepspeed_path = Path(deepspeed_path)
        self.function_summaries = {}
        self.seen_bugs = set()
        self.stats = {
            'files_analyzed': 0,
            'functions_analyzed': 0,
            'bugs_total': 0,
            'bugs_deduplicated': 0,
            'bugs_downgraded': defaultdict(int),
            'bugs_filtered': defaultdict(int)
        }
    
    def categorize_file(self, file_path: Path) -> str:
        """Categorize file type."""
        file_str = str(file_path).lower()
        
        if any(x in file_str for x in ['test', 'tests', 'testing']):
            return 'test'
        if any(x in file_str for x in ['bench', 'benchmark', 'perf', 'profile']):
            return 'benchmark'
        if any(x in file_str for x in ['example', 'examples', 'demo', 'sample', 'tutorial']):
            return 'example'
        if 'setup.py' in file_str:
            return 'setup'
        
        return 'production'
    
    def has_assert_guard(self, source_lines: List[str], target_line: int, bug_type: str) -> bool:
        """Check if there's an assert statement guarding the access."""
        # Check lines before the bug
        start = max(0, target_line - 5)
        context = source_lines[start:target_line]
        context_str = ''.join(context).lower()
        
        if bug_type == 'BOUNDS':
            # Look for assert len(...) > 0 or assert ... in ...
            if 'assert len(' in context_str or 'assert ' in context_str:
                return True
        elif bug_type == 'DIV_ZERO':
            # Look for assert ... != 0 or assert ... > 0
            if 'assert ' in context_str and ('!= 0' in context_str or '> 0' in context_str):
                return True
        
        return False
    
    def has_immediate_guard(self, source_lines: List[str], target_line: int, bug_type: str) -> bool:
        """Check if there's an immediate if-check guarding the access."""
        # Check 1-3 lines before target
        start = max(0, target_line - 3)
        context = source_lines[start:target_line]
        context_str = ''.join(context).lower()
        
        if bug_type == 'BOUNDS':
            # Pattern: if KEY in dict: ... dict[KEY]
            if ' in ' in context_str and 'if ' in context_str:
                return True
        
        return False
    
    def should_downgrade_severity(self, bug: BugReport, file_category: str, 
                                  source_line: str, source_lines: List[str] = None, 
                                  target_line: int = 0) -> tuple:
        """
        Check if bug severity should be downgraded.
        Returns: (should_downgrade, reason)
        """
        reasons = []
        
        # Test/benchmark files - downgrade to MEDIUM
        if file_category in ['test', 'benchmark', 'example', 'setup']:
            reasons.append(f'{file_category}_file')
        
        # Check for assert-based guards
        if source_lines and target_line > 0:
            if self.has_assert_guard(source_lines, target_line, bug.type):
                reasons.append('assert_guard')
            if self.has_immediate_guard(source_lines, target_line, bug.type):
                reasons.append('immediate_guard')
        
        # Config function heuristic (get_* functions in config files)
        if bug.function.startswith('get_') and 'config' in str(bug.full_path).lower():
            reasons.append('config_accessor')
        
        # Init method with defensive programming
        if bug.function in ['__init__', '__new__', '__post_init__']:
            # Count asserts in context
            if source_lines and target_line > 0:
                context = source_lines[max(0, target_line-10):target_line]
                assert_count = sum(1 for line in context if 'assert ' in line.lower())
                if assert_count >= 2:
                    reasons.append('init_with_asserts')
        
        # Safe list comprehension patterns
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
                # Check if it's a simple loop counter (these are usually safe)
                if not any(p in source_line for p in ['sum(', 'len(', 'count(']):
                    reasons.append('loop_counter_div')
        
        return len(reasons) > 0, ','.join(reasons)
    
    def analyze_function(self, func_name: str, func_code, file_path: Path, 
                        lineno: int, file_category: str) -> List[BugReport]:
        """Analyze function and return filtered bugs."""
        
        try:
            summary = analyze_code_object(
                func_code,
                func_name=func_name,
                callee_summaries=self.function_summaries
            )
        except Exception:
            return []
        
        # Store summary for interprocedural analysis
        module_name = file_path.stem
        self.function_summaries[f"{module_name}.{func_name}"] = summary
        
        # Load source for context
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
            
            # Use function line number (bug_finding doesn't have location)
            line_num = lineno
            
            # Get source line
            source_line = ""
            if 0 < line_num <= len(source_lines):
                source_line = source_lines[line_num - 1].strip()
            
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
            
            # Check for duplicates
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
            
            # Check for downgrade reasons
            if severity == 'HIGH':
                should_downgrade, reason = self.should_downgrade_severity(
                    bug, file_category, source_line, source_lines, line_num
                )
                
                if should_downgrade:
                    severity = 'MEDIUM'
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
        """Find all Python files in DeepSpeed."""
        files = []
        
        # Priority directories (production code)
        priority_dirs = [
            'deepspeed/runtime',
            'deepspeed/ops',
            'deepspeed/inference',
            'deepspeed/checkpoint',
            'deepspeed/module_inject'
        ]
        
        for priority_dir in priority_dirs:
            dir_path = self.deepspeed_path / priority_dir
            if dir_path.exists():
                for py_file in dir_path.rglob('*.py'):
                    if '__pycache__' not in str(py_file):
                        files.append(py_file)
        
        # Other directories
        for py_file in self.deepspeed_path.rglob('*.py'):
            if py_file not in files and '__pycache__' not in str(py_file):
                files.append(py_file)
        
        return files
    
    def analyze_repository(self) -> Dict:
        """Analyze entire DeepSpeed repository."""
        
        files = self.find_python_files()
        print(f"Found {len(files)} Python files to analyze")
        print()
        
        results = []
        start_time = time.time()
        
        for i, file_path in enumerate(files):
            result = self.analyze_file(file_path)
            results.append(result)
            
            if (i + 1) % 50 == 0 or i == len(files) - 1:
                elapsed = time.time() - start_time
                rate = (i + 1) / elapsed
                print(f"[{i+1}/{len(files)}] {file_path.name} ({rate:.1f} files/sec)")
        
        elapsed = time.time() - start_time
        
        return self.generate_report(results, elapsed)
    
    def generate_report(self, results: List[Dict], elapsed: float) -> Dict:
        """Generate comprehensive report."""
        
        # Collect all bugs
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
        
        bounds_bugs = [b for b in all_bugs if b['type'] == 'BOUNDS']
        divzero_bugs = [b for b in all_bugs if b['type'] == 'DIV_ZERO']
        
        # High severity by file
        bugs_by_file = defaultdict(list)
        for bug in high_severity:
            bugs_by_file[bug['file']].append(bug)
        
        top_files = sorted(
            bugs_by_file.items(),
            key=lambda x: len(x[1]),
            reverse=True
        )[:20]
        
        return {
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
                'bounds_errors': len(bounds_bugs),
                'div_zero_errors': len(divzero_bugs)
            },
            'high_severity_bugs': high_severity,
            'medium_severity_bugs': medium_severity[:100],  # Sample of medium
            'bugs_by_file': {
                file: {'count': len(bugs), 'bugs': bugs}
                for file, bugs in top_files
            },
            'comparison_to_original': {
                'note': 'Original had 989 HIGH severity from 16,049 total bugs'
            }
        }
    
    def print_summary(self, report: Dict):
        """Print human-readable summary."""
        
        print("\n" + "="*80)
        print("IMPROVED ANALYSIS RESULTS")
        print("="*80)
        print()
        
        meta = report['analysis_metadata']
        summary = report['summary']
        filtering = meta['filtering_stats']
        
        print(f"Performance:")
        print(f"  Files:     {meta['files_analyzed']}")
        print(f"  Functions: {meta['functions_analyzed']}")
        print(f"  Time:      {meta['elapsed_seconds']}s ({meta['files_per_second']:.1f} files/sec)")
        print()
        
        print(f"File categories:")
        for cat, count in sorted(meta['file_categories'].items()):
            print(f"  {cat:12s}: {count:3d}")
        print()
        
        print(f"Bug filtering:")
        print(f"  Total bugs found:  {filtering['bugs_total']}")
        print(f"  Deduplicated:      {filtering['bugs_deduplicated']}")
        print(f"  Bugs after dedup:  {filtering['bugs_total'] - filtering['bugs_deduplicated']}")
        print()
        
        if filtering['bugs_downgraded']:
            print(f"Downgrade reasons:")
            for reason, count in sorted(filtering['bugs_downgraded'].items(), key=lambda x: -x[1]):
                print(f"  {reason:30s}: {count:3d}")
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
        print(f"  BOUNDS:        {summary['bounds_errors']}")
        print(f"  DIV_ZERO:      {summary['div_zero_errors']}")
        print()
        
        # Comparison
        print("="*80)
        print("COMPARISON TO ORIGINAL")
        print("="*80)
        print()
        print(f"Original analyzer:")
        print(f"  16,049 total bugs")
        print(f"     989 HIGH severity (6.2%)")
        print()
        print(f"Improved analyzer:")
        print(f"  {summary['total_bugs']:5d} total bugs")
        print(f"  {summary['high_severity']:5d} HIGH severity ({100*summary['high_severity']/max(1,summary['total_bugs']):.1f}%)")
        print()
        
        if summary['high_severity'] > 0:
            improvement = 989 - summary['high_severity']
            pct = 100 * improvement / 989
            print(f"Improvement: {improvement} fewer HIGH severity bugs ({pct:.1f}% reduction)")
            print()
        
        # Show sample HIGH severity bugs
        high_bugs = report['high_severity_bugs']
        if high_bugs:
            print("="*80)
            print("SAMPLE HIGH SEVERITY BUGS (likely real issues)")
            print("="*80)
            print()
            for i, bug in enumerate(high_bugs[:15], 1):
                print(f"{i}. {bug['type']} in {bug['file']}:{bug['function']}()")
                print(f"   Line {bug['line']}, confidence {bug['confidence']:.2f}")
                print(f"   {bug['message']}")
                print()

def main():
    """Main entry point."""
    deepspeed_path = Path(__file__).parent / 'external_tools' / 'DeepSpeed'
    
    if not deepspeed_path.exists():
        print(f"Error: DeepSpeed not found at {deepspeed_path}")
        return 1
    
    print("="*80)
    print("IMPROVED DEEPSPEED ANALYZER - BALANCED FILTERING")
    print("="*80)
    print()
    print("Improvements:")
    print("  1. Deduplicate identical bug reports")
    print("  2. Downgrade test/benchmark/example file bugs to MEDIUM")
    print("  3. Downgrade safe patterns (list comp + range, iterators)")
    print("  4. Keep all bugs for review, just categorize better")
    print()
    print(f"Target: {deepspeed_path}")
    print()
    
    analyzer = BalancedDeepSpeedAnalyzer(str(deepspeed_path))
    report = analyzer.analyze_repository()
    
    # Save report
    output_file = Path(__file__).parent / 'results' / 'deepspeed_balanced_analysis.json'
    output_file.parent.mkdir(exist_ok=True)
    
    with open(output_file, 'w') as f:
        json.dump(report, f, indent=2)
    
    print(f"\nReport saved to: {output_file}")
    
    # Print summary
    analyzer.print_summary(report)
    
    # Return exit code based on HIGH severity count
    if report['summary']['high_severity'] > 0:
        return 1
    
    return 0

if __name__ == '__main__':
    sys.exit(main())
