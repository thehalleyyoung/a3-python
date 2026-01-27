#!/usr/bin/env python3
"""
Poetry DSE Validation - Iteration 149
Validate 5 bugs from tier 3 poetry scan (iteration 148).
"""
import json
import sys
from pathlib import Path

# Add pyfromscratch to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from pyfromscratch.analyzer import Analyzer
from datetime import datetime, timezone

def main():
    scan_file = Path("results/public_repos/poetry_tier3_scan_iter148.json")
    
    with open(scan_file) as f:
        scan_data = json.load(f)
    
    # Extract bugs
    bugs = [
        (file_path, result)
        for file_path, result in scan_data["results"].items()
        if result["status"] == "BUG"
    ]
    
    print(f"Poetry DSE Validation - Iteration 149")
    print(f"Scan date: {scan_data['scan_date']}")
    print(f"Total bugs to validate: {len(bugs)}\n")
    
    validation_results = {
        "iteration": 149,
        "scan_iteration": 148,
        "scan_date": scan_data["scan_date"],
        "validation_date": datetime.now(timezone.utc).isoformat(),
        "repo": "poetry",
        "total_bugs": len(bugs),
        "validated": 0,
        "false_positives": 0,
        "bugs": [],
        "by_type": {}
    }
    
    for i, (file_path, result) in enumerate(bugs, 1):
        print(f"\n{'='*80}")
        print(f"Bug {i}/{len(bugs)}: {file_path}")
        print(f"{'='*80}")
        
        # Extract bug details from output
        output = result.get("output", "")
        lines = output.split("\n")
        
        bug_type = None
        function_name = None
        exception_type = None
        
        for line in lines:
            if line.startswith("BUG:"):
                bug_type = line.split(":")[1].strip().split()[0]
            elif "function:" in line.lower():
                parts = line.split(":")
                if len(parts) >= 2:
                    function_name = parts[1].strip()
            elif "exception" in line.lower() and ":" in line:
                parts = line.split(":")
                if len(parts) >= 2 and not line.startswith("BUG"):
                    exception_type = parts[1].strip().split()[0]
        
        print(f"Bug type: {bug_type}")
        print(f"Function: {function_name}")
        print(f"Exception: {exception_type}")
        
        # Strip results/public_repos/clones/ prefix to get actual path
        actual_path = Path(file_path)
        if not actual_path.exists():
            print(f"✗ File not found: {actual_path}")
            bug_record = {
                "file": file_path,
                "bug_type": bug_type,
                "function": function_name,
                "exception": exception_type,
                "validated": False,
                "error": "file_not_found"
            }
            validation_results["bugs"].append(bug_record)
            validation_results["false_positives"] += 1
            continue
        
        # Try DSE validation with re-analysis
        try:
            analyzer = Analyzer(max_paths=200, max_depth=100, verbose=False)
            result_obj = analyzer.analyze_file(actual_path)
            
            is_validated = False
            if result_obj.verdict == "BUG":
                if result_obj.counterexample:
                    is_validated = result_obj.counterexample.get("dse_validated", False)
                    concrete_repro = result_obj.counterexample.get("concrete_repro")
                    
                    if is_validated:
                        print(f"✓ DSE validated: {concrete_repro}")
                    else:
                        print(f"✗ DSE could not validate within budget")
                else:
                    print(f"✗ No counterexample generated")
            else:
                print(f"✗ Analyzer verdict: {result_obj.verdict} (expected BUG)")
            
            bug_record = {
                "file": file_path,
                "bug_type": bug_type,
                "function": function_name,
                "exception": exception_type,
                "validated": is_validated
            }
            
            validation_results["bugs"].append(bug_record)
            
            if is_validated:
                validation_results["validated"] += 1
            else:
                validation_results["false_positives"] += 1
                
        except Exception as e:
            print(f"✗ VALIDATION ERROR: {e}")
            bug_record = {
                "file": file_path,
                "bug_type": bug_type,
                "function": function_name,
                "exception": exception_type,
                "validated": False,
                "error": str(e)
            }
            validation_results["bugs"].append(bug_record)
            validation_results["false_positives"] += 1
    
    # Aggregate by type
    for bug in validation_results["bugs"]:
        bug_type = bug.get("bug_type", "UNKNOWN")
        if bug_type not in validation_results["by_type"]:
            validation_results["by_type"][bug_type] = {
                "total": 0,
                "validated": 0,
                "rate": 0.0
            }
        validation_results["by_type"][bug_type]["total"] += 1
        if bug["validated"]:
            validation_results["by_type"][bug_type]["validated"] += 1
    
    # Calculate rates per type
    for bug_type, stats in validation_results["by_type"].items():
        if stats["total"] > 0:
            stats["rate"] = stats["validated"] / stats["total"]
    
    # Calculate rates
    validation_results["validation_rate"] = (
        validation_results["validated"] / validation_results["total_bugs"]
        if validation_results["total_bugs"] > 0 else 0
    )
    validation_results["false_positive_rate"] = (
        validation_results["false_positives"] / validation_results["total_bugs"]
        if validation_results["total_bugs"] > 0 else 0
    )
    validation_results["true_bug_rate"] = (
        validation_results["validated"] / 100  # 100 files scanned
    )
    
    # Summary
    print(f"\n{'='*80}")
    print(f"VALIDATION SUMMARY")
    print(f"{'='*80}")
    print(f"Total bugs: {validation_results['total_bugs']}")
    print(f"Validated (real bugs): {validation_results['validated']}")
    print(f"False positives: {validation_results['false_positives']}")
    print(f"Validation rate: {validation_results['validation_rate']:.1%}")
    print(f"False positive rate: {validation_results['false_positive_rate']:.1%}")
    print(f"True bug rate: {validation_results['true_bug_rate']:.1%}")
    
    # Save results
    output_file = Path("results/public_repos/poetry_dse_validation_iter149.json")
    with open(output_file, 'w') as f:
        json.dump(validation_results, f, indent=2)
    
    print(f"\nResults saved to: {output_file}")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
