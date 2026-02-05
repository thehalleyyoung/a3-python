#!/usr/bin/env python3
"""
Improved DeepSpeed analyzer with enhanced false positive filtering.

Improvements:
1. Deduplicate bug reports (same location = one report)
2. Filter test/benchmark/example files
3. Better handling of list comprehensions and iterators
4. String operation context awareness
5. Dataflow confirmation for bounds/div-zero
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

# Files to exclude from analysis
EXCLUDED_PATTERNS = [
    'test', 'tests', 'testing',
    'bench', 'benchmark', 'perf', 'profile',
    'example', 'examples', 'demo', 'sample', 'tutorial',
    'setup.py', '__pycache__'
]

@dataclass
class BugReport:
    """Enhanced bug report with deduplication support."""
    type: str
    file: str
    function: str
    line: int
    confidence: float
    severity: str
    message: str
    full_path: str
    is_guarded: bool = False
    source_line: str = ""
    
    def key(self):
        """Unique key for deduplication."""
        return (self.file, self.function, self.line, self.type)

@dataclass
class FunctionAnalysisResult:
    """Result from analyzing a function."""
    name: str
    returns_empty: bool
    returns_bounds: tuple
    bugs: List[BugReport]

class ImprovedDeepSpeedAnalyzer:
    """Enhanced analyzer with FP filtering."""
    
    def __init__(self, deepspeed_path: str):
        self.deepspeed_path = Path(deepspeed_path)
        self.function_summaries = {}
        self.seen_bugs = set()  # For deduplication
        self.stats = {
            'files_analyzed': 0,
            'functions_analyzed': 0,
            'bugs_filtered': defaultdict(int),
            'bugs_kept': 0
        }
    
    def should_exclude_file(self, file_path: Path) -> bool:
        """Check if file should be excluded from analysis."""
        file_str = str(file_path).lower()
        return any(pattern in file_str for pattern in EXCLUDED_PATTERNS)
    
    def is_safe_pattern(self, bug: BugReport, source_lines: List[str]) -> tuple:
        """
        Check if bug matches a known safe pattern.
        Returns: (is_safe, reason)
        """
        if bug.line > len(source_lines):
            return False, None
        
        line = source_lines[bug.line - 1].strip()
        
        # List comprehension with range(len(...))
        if '[' in line and 'for' in line and 'range(len(' in line:
            return True, 'list_comprehension_range'
        
        # Iterator patterns
        if any(pattern in line for pattern in ['enumerate(', 'zip(', 'iter(']):
            return True, 'iterator_pattern'
        
        # String split patterns (often safe)
        if bug.type == 'BOUNDS' and '.split(' in line and '[' in line:
            # Check if it's immediate split()[idx]
            if '.split(' in line and '][' not in line:  # single index
                return True, 'string_split_single_index'
        
        # Division in mathematical context (not user data)
        if bug.type == 'DIV_ZERO':
            # Check if denominator is from statistical operations
            context = ' '.join(source_lines[max(0, bug.line-3):bug.line+2])
            if any(x in context for x in ['mean(', 'sum(', 'count(', 'len(']):
                # Check if numerator is also from same collection
                if 'sum(' in line and 'len(' in line:
                    # sum(x)/len(x) pattern - could be empty
                    return False, None
            
            # Loop counters and accumulators
            if any(x in line for x in ['/ i', '/ count', '/ total', '/ n_']):
                # Check if there's a loop or initialization
                prev_lines = source_lines[max(0, bug.line-5):bug.line-1]
                if any('for ' in l or 'while ' in l for l in prev_lines):
                    return True, 'loop_counter'
        
        return False, None
    
    def analyze_function_with_filtering(self, func_name: str, func_code, 
                                       file_path: Path, lineno: int,
                                       source_lines: List[str]) -> FunctionAnalysisResult:
        """Analyze function and filter false positives."""
        
        try:
            summary = analyze_code_object(
                func_code,
                func_name=func_name,
                callee_summaries=self.function_summaries
            )
        except Exception as e:
            return FunctionAnalysisResult(func_name, False, (None, None), [])
        
        # Store summary for interprocedural analysis
        module_name = file_path.stem
        self.function_summaries[f"{module_name}.{func_name}"] = summary
        
        # Extract and filter bugs
        bugs = []
        for bug_finding in summary.bugs:
            if bug_finding.type not in NON_SECURITY_BUGS:
                continue
            
            # Extract line number
            location_parts = bug_finding.location.split(':')
            if len(location_parts) >= 2:
                try:
                    line_num = int(location_parts[1])
                except:
                    continue
            else:
                continue
            
            # Check for safe patterns first
            bug_obj = BugReport(
                type=bug_finding.type,
                file=file_path.name,
                function=func_name,
                line=line_num,
                confidence=bug_finding.confidence,
                severity='',
                message=bug_finding.message,
                full_path=str(file_path),
                is_guarded=bug_finding.is_guarded,
                source_line=source_lines[line_num-1] if line_num <= len(source_lines) else ""
            )
            
            # Check if duplicate
            bug_key = bug_obj.key()
            if bug_key in self.seen_bugs:
                self.stats['bugs_filtered']['duplicate'] += 1
                continue
            
            # Check safe patterns
            is_safe, reason = self.is_safe_pattern(bug_obj, source_lines)
            if is_safe:
                self.stats['bugs_filtered'][reason] += 1
                continue
            
            # Categorize severity
            confidence = bug_finding.confidence
            is_guarded = bug_finding.is_guarded
            
            if is_guarded:
                severity = 'LOW'
                self.stats['bugs_filtered']['guarded'] += 1
                continue
            elif confidence >= HIGH_CONFIDENCE_THRESHOLD:
                severity = 'HIGH'
            elif confidence >= MEDIUM_CONFIDENCE_THRESHOLD:
                severity = 'MEDIUM'
            else:
                severity = 'LOW'
                self.stats['bugs_filtered']['low_confidence'] += 1
                continue
            
            bug_obj.severity = severity
            bugs.append(bug_obj)
            self.seen_bugs.add(bug_key)
            self.stats['bugs_kept'] += 1
        
        # Extract return info
        returns_empty = summary.returns_empty == 'EMPTY'
        returns_bounds = summary.returns_bounds or (None, None)
        
        return FunctionAnalysisResult(func_name, returns_empty, returns_bounds, bugs)
    
    def analyze_file(self, file_path: Path) -> Dict:
        """Analyze a single Python file."""
        
        # Check if should exclude
        if self.should_exclude_file(file_path):
            return {
                'file': file_path.name,
                'excluded': True,
                'reason': 'test/benchmark/example file'
            }
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                source = f.read()
                source_lines = source.splitlines()
        except:
            return {'file': file_path.name, 'error': 'read_failed'}
        
        try:
            tree = ast.parse(source)
        except:
            return {'file': file_path.name, 'error': 'parse_failed'}
        
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
        bugs = []
        for func_info in functions:
            try:
                func_code = compile(
                    ast.Module(body=[func_info['node']], type_ignores=[]),
                    filename=str(file_path),
                    mode='exec'
                ).co_consts[0]
                
                result = self.analyze_function_with_filtering(
                    func_info['name'],
                    func_code,
                    file_path,
                    func_info['lineno'],
                    source_lines
                )
                
                bugs.extend(result.bugs)
                self.stats['functions_analyzed'] += 1
                
            except:
                pass
        
        self.stats['files_analyzed'] += 1
        
        return {
            'file': file_path.name,
            'functions': len(functions),
            'bugs': [asdict(b) for b in bugs]
        }
    
    def find_python_files(self) -> List[Path]:
        """Find all Python files in DeepSpeed."""
        files = []
        
        # Priority directories
        priority_dirs = ['deepspeed/runtime', 'deepspeed/ops', 'deepspeed/inference']
        
        for priority_dir in priority_dirs:
            dir_path = self.deepspeed_path / priority_dir
            if dir_path.exists():
                files.extend(dir_path.rglob('*.py'))
        
        # Other directories
        for py_file in self.deepspeed_path.rglob('*.py'):
            if py_file not in files and '__pycache__' not in str(py_file):
                files.append(py_file)
        
        return files
    
    def analyze_repository(self) -> Dict:
        """Analyze entire DeepSpeed repository."""
        
        files = self.find_python_files()
        print(f"Found {len(files)} Python files to analyze")
        print(f"Filtering out test/benchmark/example files...")
        print()
        
        results = []
        start_time = time.time()
        
        for i, file_path in enumerate(files):
            result = self.analyze_file(file_path)
            results.append(result)
            
            if (i + 1) % 10 == 0 or i == len(files) - 1:
                elapsed = time.time() - start_time
                rate = (i + 1) / elapsed
                print(f"[{i+1}/{len(files)}] {file_path.name} ({rate:.1f} files/sec)")
        
        elapsed = time.time() - start_time
        
        return self.generate_report(results, elapsed)
    
    def generate_report(self, results: List[Dict], elapsed: float) -> Dict:
        """Generate comprehensive report."""
        
        # Collect all bugs
        all_bugs = []
        excluded_count = 0
        
        for result in results:
            if result.get('excluded'):
                excluded_count += 1
            elif 'bugs' in result:
                all_bugs.extend(result['bugs'])
        
        # Categorize bugs
        high_severity = [b for b in all_bugs if b['severity'] == 'HIGH']
        medium_severity = [b for b in all_bugs if b['severity'] == 'MEDIUM']
        low_severity = [b for b in all_bugs if b['severity'] == 'LOW']
        
        bounds_bugs = [b for b in all_bugs if b['type'] == 'BOUNDS']
        divzero_bugs = [b for b in all_bugs if b['type'] == 'DIV_ZERO']
        
        # Group by file
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
                'files_excluded': excluded_count,
                'functions_analyzed': self.stats['functions_analyzed'],
                'elapsed_seconds': round(elapsed, 2),
                'files_per_second': round(self.stats['files_analyzed'] / elapsed, 2),
                'filtering_stats': dict(self.stats['bugs_filtered'])
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
            'bugs_by_file': {
                file: {'count': len(bugs), 'bugs': bugs}
                for file, bugs in top_files
            }
        }
    
    def print_summary(self, report: Dict):
        """Print human-readable summary."""
        
        print("\n" + "="*80)
        print("IMPROVED ANALYSIS SUMMARY")
        print("="*80)
        print()
        
        meta = report['analysis_metadata']
        summary = report['summary']
        
        print(f"Files analyzed: {meta['files_analyzed']}")
        print(f"Files excluded: {meta['files_excluded']}")
        print(f"Functions analyzed: {meta['functions_analyzed']}")
        print(f"Time: {meta['elapsed_seconds']}s ({meta['files_per_second']} files/sec)")
        print()
        
        print("Bugs filtered:")
        for reason, count in sorted(meta['filtering_stats'].items(), key=lambda x: -x[1]):
            print(f"  {reason:30s}: {count:4d}")
        print()
        
        print(f"Total bugs found: {summary['total_bugs']}")
        print(f"  HIGH severity:   {summary['high_severity']}")
        print(f"  MEDIUM severity: {summary['medium_severity']}")
        print(f"  LOW severity:    {summary['low_severity']}")
        print()
        
        print(f"By type:")
        print(f"  BOUNDS:   {summary['bounds_errors']}")
        print(f"  DIV_ZERO: {summary['div_zero_errors']}")
        print()
        
        # Show top HIGH severity bugs
        high_bugs = report['high_severity_bugs']
        if high_bugs:
            print("Top 10 HIGH severity bugs:")
            for i, bug in enumerate(high_bugs[:10], 1):
                print(f"{i}. {bug['type']} in {bug['file']}:{bug['function']}() line {bug['line']}")
                print(f"   Confidence: {bug['confidence']:.2f}")
                if bug['source_line']:
                    print(f"   Code: {bug['source_line'][:70]}")
                print()

def main():
    """Main entry point."""
    deepspeed_path = Path(__file__).parent / 'external_tools' / 'DeepSpeed'
    
    if not deepspeed_path.exists():
        print(f"Error: DeepSpeed not found at {deepspeed_path}")
        return 1
    
    print("Starting improved DeepSpeed analysis...")
    print(f"Target: {deepspeed_path}")
    print()
    
    analyzer = ImprovedDeepSpeedAnalyzer(str(deepspeed_path))
    report = analyzer.analyze_repository()
    
    # Save report
    output_file = Path(__file__).parent / 'results' / 'deepspeed_improved_analysis.json'
    output_file.parent.mkdir(exist_ok=True)
    
    with open(output_file, 'w') as f:
        json.dump(report, f, indent=2)
    
    print(f"\nReport saved to: {output_file}")
    
    # Print summary
    analyzer.print_summary(report)
    
    # Return exit code
    if report['summary']['high_severity'] > 0:
        print(f"\nFound {report['summary']['high_severity']} HIGH severity bugs")
        return 1
    
    return 0

if __name__ == '__main__':
    sys.exit(main())
