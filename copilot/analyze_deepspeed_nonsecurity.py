#!/usr/bin/env python3
"""
Comprehensive DeepSpeed analysis focusing on non-security bugs (BOUNDS, DIV_ZERO).
Uses enhanced interprocedural analysis to maximize TPs and minimize FPs.
"""

import sys
import os
import json
from pathlib import Path
from collections import defaultdict
from dataclasses import dataclass, asdict
from typing import List, Dict, Set
import time

# Add parent to path
sys.path.insert(0, str(Path(__file__).parent))

from pyfromscratch.semantics.bytecode_summaries import analyze_code_object
import ast
import dis

DEEPSPEED_PATH = Path(__file__).parent / "external_tools" / "DeepSpeed"

# Non-security bug types we care about
NON_SECURITY_BUGS = {'BOUNDS', 'DIV_ZERO'}

# High confidence threshold for reporting
HIGH_CONFIDENCE_THRESHOLD = 0.8
MEDIUM_CONFIDENCE_THRESHOLD = 0.5

@dataclass
class BugReport:
    """Structured bug report."""
    file_path: str
    function_name: str
    line_number: int
    bug_type: str
    confidence: float
    is_guarded: bool
    context: str
    severity: str  # HIGH, MEDIUM, LOW

@dataclass
class FunctionAnalysisResult:
    """Result of analyzing a single function."""
    function_name: str
    bugs: List[BugReport]
    has_bounds: bool
    has_div_zero: bool
    return_len_bounds: tuple  # (lower, upper)
    return_emptiness: int


class DeepSpeedBytecodeAnalyzer:
    """Analyzes DeepSpeed using enhanced bytecode analysis."""
    
    def __init__(self, repo_path: Path):
        self.repo_path = repo_path
        self.function_summaries: Dict[str, any] = {}
        self.all_bugs: List[BugReport] = []
        self.files_analyzed = 0
        self.functions_analyzed = 0
        self.start_time = time.time()
        
    def find_python_files(self) -> List[Path]:
        """Find all Python files in DeepSpeed."""
        python_files = []
        
        # Prioritize files likely to have non-security bugs
        priority_dirs = [
            'deepspeed/runtime',
            'deepspeed/ops',
            'deepspeed/inference',
            'deepspeed/checkpoint',
            'deepspeed/utils',
            'deepspeed/monitor',
        ]
        
        for priority_dir in priority_dirs:
            dir_path = self.repo_path / priority_dir
            if dir_path.exists():
                python_files.extend(dir_path.rglob('*.py'))
        
        # Add other files
        for file_path in self.repo_path.rglob('*.py'):
            if file_path not in python_files:
                # Skip test files and __pycache__
                if '__pycache__' in str(file_path) or '/tests/' in str(file_path):
                    continue
                python_files.append(file_path)
        
        return sorted(set(python_files))
    
    def extract_functions(self, source_code: str) -> List[tuple]:
        """Extract all function definitions from source code."""
        try:
            tree = ast.parse(source_code)
            functions = []
            
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef):
                    # Get function name and line number
                    functions.append((node.name, node.lineno, node))
            
            return functions
        except:
            return []
    
    def analyze_function(self, func_name: str, func_code, file_path: str, 
                        lineno: int) -> FunctionAnalysisResult:
        """Analyze a single function with interprocedural context."""
        try:
            # Analyze with available summaries
            summary = analyze_code_object(
                func_code,
                func_name=func_name,
                callee_summaries=self.function_summaries
            )
            
            # Store summary for interprocedural use
            summary_key = f"{Path(file_path).stem}.{func_name}"
            self.function_summaries[summary_key] = summary
            
            # Extract bugs
            bugs = []
            has_bounds = False
            has_div_zero = False
            
            for bug in summary.potential_bugs:
                if bug.bug_type not in NON_SECURITY_BUGS:
                    continue
                
                if bug.bug_type == 'BOUNDS':
                    has_bounds = True
                elif bug.bug_type == 'DIV_ZERO':
                    has_div_zero = True
                
                # Determine severity
                confidence = bug.confidence
                is_guarded = bug.is_guarded
                
                if is_guarded:
                    severity = 'LOW'  # Guarded bugs are less concerning
                elif confidence >= HIGH_CONFIDENCE_THRESHOLD:
                    severity = 'HIGH'
                elif confidence >= MEDIUM_CONFIDENCE_THRESHOLD:
                    severity = 'MEDIUM'
                else:
                    severity = 'LOW'
                
                # Extract context from message
                context = bug.message[:100] if bug.message else ""
                
                bug_report = BugReport(
                    file_path=str(file_path),
                    function_name=func_name,
                    line_number=lineno,  # Function start line
                    bug_type=bug.bug_type,
                    confidence=confidence,
                    is_guarded=is_guarded,
                    context=context,
                    severity=severity
                )
                bugs.append(bug_report)
            
            return FunctionAnalysisResult(
                function_name=func_name,
                bugs=bugs,
                has_bounds=has_bounds,
                has_div_zero=has_div_zero,
                return_len_bounds=(
                    summary.return_len_lower_bound,
                    summary.return_len_upper_bound
                ),
                return_emptiness=summary.return_emptiness
            )
            
        except Exception as e:
            # Silent failure - just return empty result
            return FunctionAnalysisResult(
                function_name=func_name,
                bugs=[],
                has_bounds=False,
                has_div_zero=False,
                return_len_bounds=(None, None),
                return_emptiness=3  # TOP
            )
    
    def analyze_file(self, file_path: Path) -> List[BugReport]:
        """Analyze a single file."""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                source_code = f.read()
            
            # Extract functions
            functions = self.extract_functions(source_code)
            
            file_bugs = []
            
            # Analyze each function
            for func_name, lineno, func_node in functions:
                try:
                    # Compile function to code object
                    func_code = compile(
                        ast.Module(body=[func_node], type_ignores=[]),
                        filename=str(file_path),
                        mode='exec'
                    )
                    
                    # Get the function's code object
                    for const in func_code.co_consts:
                        if hasattr(const, 'co_name') and const.co_name == func_name:
                            result = self.analyze_function(
                                func_name, const, file_path, lineno
                            )
                            file_bugs.extend(result.bugs)
                            self.functions_analyzed += 1
                            break
                
                except Exception as e:
                    # Skip functions that can't be compiled
                    continue
            
            return file_bugs
            
        except Exception as e:
            return []
    
    def analyze_repository(self, max_files: int = None) -> Dict:
        """Analyze the entire DeepSpeed repository."""
        print(f"{'='*80}")
        print(f"DEEPSPEED NON-SECURITY BUG ANALYSIS")
        print(f"Using Enhanced Interprocedural Bytecode Analysis")
        print(f"{'='*80}\n")
        
        python_files = self.find_python_files()
        
        if max_files:
            python_files = python_files[:max_files]
        
        print(f"Found {len(python_files)} Python files to analyze\n")
        
        # Analyze files
        for i, file_path in enumerate(python_files, 1):
            rel_path = file_path.relative_to(self.repo_path)
            
            if i % 10 == 0 or i == 1:
                elapsed = time.time() - self.start_time
                rate = i / elapsed if elapsed > 0 else 0
                print(f"[{i}/{len(python_files)}] {rel_path} ({rate:.1f} files/sec)")
            
            file_bugs = self.analyze_file(file_path)
            self.all_bugs.extend(file_bugs)
            self.files_analyzed += 1
        
        return self.generate_report()
    
    def generate_report(self) -> Dict:
        """Generate comprehensive analysis report."""
        
        # Categorize bugs
        high_severity = [b for b in self.all_bugs if b.severity == 'HIGH']
        medium_severity = [b for b in self.all_bugs if b.severity == 'MEDIUM']
        low_severity = [b for b in self.all_bugs if b.severity == 'LOW']
        
        # Group by bug type
        bounds_bugs = [b for b in self.all_bugs if b.bug_type == 'BOUNDS']
        div_zero_bugs = [b for b in self.all_bugs if b.bug_type == 'DIV_ZERO']
        
        # Group by file
        bugs_by_file = defaultdict(list)
        for bug in self.all_bugs:
            bugs_by_file[bug.file_path].append(bug)
        
        # High confidence bugs (likely TPs)
        high_confidence_bugs = [b for b in self.all_bugs if b.confidence >= HIGH_CONFIDENCE_THRESHOLD]
        
        elapsed = time.time() - self.start_time
        
        report = {
            'analysis_metadata': {
                'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                'elapsed_seconds': round(elapsed, 2),
                'files_analyzed': self.files_analyzed,
                'functions_analyzed': self.functions_analyzed,
                'analysis_rate': round(self.files_analyzed / elapsed, 2) if elapsed > 0 else 0
            },
            'summary': {
                'total_bugs': len(self.all_bugs),
                'high_severity': len(high_severity),
                'medium_severity': len(medium_severity),
                'low_severity': len(low_severity),
                'bounds_bugs': len(bounds_bugs),
                'div_zero_bugs': len(div_zero_bugs),
                'high_confidence_bugs': len(high_confidence_bugs),
                'files_with_bugs': len(bugs_by_file)
            },
            'high_confidence_findings': [
                {
                    'file': Path(b.file_path).name,
                    'full_path': b.file_path,
                    'function': b.function_name,
                    'line': b.line_number,
                    'type': b.bug_type,
                    'confidence': round(b.confidence, 2),
                    'guarded': b.is_guarded,
                    'severity': b.severity,
                    'context': b.context
                }
                for b in sorted(high_confidence_bugs, key=lambda x: -x.confidence)
            ],
            'bugs_by_file': {
                Path(fp).relative_to(self.repo_path).as_posix(): [
                    {
                        'function': b.function_name,
                        'line': b.line_number,
                        'type': b.bug_type,
                        'confidence': round(b.confidence, 2),
                        'severity': b.severity
                    }
                    for b in bugs
                ]
                for fp, bugs in sorted(bugs_by_file.items(), 
                                      key=lambda x: len(x[1]), 
                                      reverse=True)[:20]  # Top 20 files
            }
        }
        
        return report
    
    def print_summary(self, report: Dict):
        """Print human-readable summary."""
        print(f"\n{'='*80}")
        print(f"ANALYSIS COMPLETE")
        print(f"{'='*80}\n")
        
        meta = report['analysis_metadata']
        summary = report['summary']
        
        print(f"Analyzed: {meta['files_analyzed']} files, {meta['functions_analyzed']} functions")
        print(f"Time: {meta['elapsed_seconds']}s ({meta['analysis_rate']} files/sec)\n")
        
        print(f"{'='*80}")
        print(f"FINDINGS SUMMARY")
        print(f"{'='*80}\n")
        
        print(f"Total non-security bugs found: {summary['total_bugs']}")
        print(f"  • BOUNDS: {summary['bounds_bugs']}")
        print(f"  • DIV_ZERO: {summary['div_zero_bugs']}\n")
        
        print(f"By Severity:")
        print(f"  • HIGH:   {summary['high_severity']} (likely true positives)")
        print(f"  • MEDIUM: {summary['medium_severity']} (needs review)")
        print(f"  • LOW:    {summary['low_severity']} (guarded or low confidence)\n")
        
        print(f"High Confidence (≥{HIGH_CONFIDENCE_THRESHOLD}) Bugs: {summary['high_confidence_bugs']}")
        print(f"Files with bugs: {summary['files_with_bugs']}\n")
        
        if report['high_confidence_findings']:
            print(f"{'='*80}")
            print(f"HIGH CONFIDENCE FINDINGS (Top 10)")
            print(f"{'='*80}\n")
            
            for i, bug in enumerate(report['high_confidence_findings'][:10], 1):
                print(f"{i}. {bug['type']} in {bug['file']}:{bug['function']}()")
                print(f"   Line: {bug['line']}, Confidence: {bug['confidence']}")
                print(f"   Severity: {bug['severity']}, Guarded: {bug['guarded']}")
                if bug['context']:
                    print(f"   Context: {bug['context']}")
                print()


def main():
    """Main entry point."""
    if not DEEPSPEED_PATH.exists():
        print(f"❌ DeepSpeed not found at {DEEPSPEED_PATH}")
        print(f"   Please ensure DeepSpeed is cloned to external_tools/")
        return 1
    
    # Parse arguments
    max_files = None
    if len(sys.argv) > 1:
        try:
            max_files = int(sys.argv[1])
            print(f"Limiting analysis to first {max_files} files\n")
        except:
            pass
    
    # Create analyzer
    analyzer = DeepSpeedBytecodeAnalyzer(DEEPSPEED_PATH)
    
    # Run analysis
    report = analyzer.analyze_repository(max_files=max_files)
    
    # Print summary
    analyzer.print_summary(report)
    
    # Save detailed report
    output_file = Path(__file__).parent / 'results' / 'deepspeed_nonsecurity_analysis.json'
    output_file.parent.mkdir(exist_ok=True)
    
    with open(output_file, 'w') as f:
        json.dump(report, f, indent=2)
    
    print(f"{'='*80}")
    print(f"Detailed report saved to: {output_file}")
    print(f"{'='*80}\n")
    
    # Return exit code based on high severity bugs
    return 0 if report['summary']['high_severity'] == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
