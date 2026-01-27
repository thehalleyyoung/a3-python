"""Check DIV_ZERO in production code across repos."""
from pyfromscratch.cfg.call_graph import build_call_graph_from_directory
from pyfromscratch.semantics.crash_summaries import BytecodeCrashSummaryComputer
from pathlib import Path

repos = ['Counterfit', 'Presidio', 'RESTler', 'Guidance', 'FLAML', 
         'GraphRAG', 'RDAgent', 'MSTICPY', 'SemanticKernel']

base = Path('/Users/halleyyoung/Documents/PythonFromScratch/external_tools')

print("DIV_ZERO in Production Code (Likely True Positives):\n")
print("="*60)

for repo_name in repos:
    path = base / repo_name
    if not path.exists():
        continue
    
    try:
        cg = build_call_graph_from_directory(path)
        computer = BytecodeCrashSummaryComputer(cg)
        summaries = computer.compute_all()
        
        # Filter for DIV_ZERO in non-test code
        true_positives = []
        for name, summ in summaries.items():
            if 'DIV_ZERO' in summ.may_trigger and 'DIV_ZERO' not in summ.guarded_bugs:
                # Filter out test files
                if 'test' not in name.lower() and 'conftest' not in name.lower():
                    true_positives.append(name)
        
        if true_positives:
            print(f"\n{repo_name}: {len(true_positives)} potential DIV_ZERO")
            for tp in true_positives[:5]:
                print(f"  {tp}")
            if len(true_positives) > 5:
                print(f"  ... and {len(true_positives) - 5} more")
        else:
            print(f"\n{repo_name}: 0 DIV_ZERO in prod code")
            
    except Exception as e:
        print(f"\n{repo_name}: Error - {e}")
