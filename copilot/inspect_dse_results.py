"""Inspect DSE results from full analysis."""
import pickle

with open('results/full_analysis_results.pkl', 'rb') as f:
    results = pickle.load(f)

print('Keys:', list(results.keys()))
print()

dse = results.get('dse_results', {})
print(f'DSE results: {len(dse)} entries')

fps = {k: v for k, v in dse.items() if v[0] == 'unreachable'}
tps = {k: v for k, v in dse.items() if v[0] == 'reachable'}
print(f'  Confirmed FP (unreachable): {len(fps)}')
print(f'  Confirmed TP (reachable):   {len(tps)}')
print()

print('=== DSE-CONFIRMED FPs (unreachable bugs) ===')
for name, (status, bug_type, cex) in sorted(fps.items()):
    print(f'  FP: {bug_type:12s} {name}')

print()
print('=== SAMPLE DSE-CONFIRMED TPs (first 15) ===')
for i, (name, (status, bug_type, cex)) in enumerate(sorted(tps.items())[:15]):
    cex_str = str(cex)[:80] if cex else 'None'
    print(f'  TP: {bug_type:12s} {name}')
    print(f'      counterexample: {cex_str}')
