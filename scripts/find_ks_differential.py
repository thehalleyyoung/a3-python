#!/usr/bin/env python3
"""Find cases where Full A3 (with kitchensink) diagnoses a bug
but A3 minus kitchensink does not."""

import json
import sys
import os

def main():
    # Try multiple ablation result files
    candidates = [
        "results/ablation_differential.json",
        "results/ablation_full.json",
    ]
    
    for cand in candidates:
        if os.path.exists(cand):
            print(f"=== Analyzing {cand} ===")
            with open(cand) as f:
                data = json.load(f)
            analyze(data, cand)
            print()

def analyze(data, source):
    print(f"Total bugs: {len(data)}")
    
    # Print config names from first entry
    if data:
        first = data[0]
        configs = first.get("configs", {})
        print(f"Config names: {list(configs.keys())}")
    
    # Find the kitchensink config key
    ks_key = None
    full_key = None
    for k in configs.keys():
        if "Kitchensink" in k or "kitchensink" in k or "KS" in k:
            ks_key = k
        if "Full" in k:
            full_key = k
    
    if not ks_key or not full_key:
        print(f"  Could not find kitchensink/full config keys: {list(configs.keys())}")
        return
    
    print(f"Full config key: {full_key!r}")
    print(f"KS config key:   {ks_key!r}")
    print()
    
    # Broader analysis: any difference where Full finds more
    ks_differential = []
    full_finds_more_findings = []
    
    for b in data:
        cfgs = b.get("configs", {})
        full = cfgs.get(full_key, {})
        noks = cfgs.get(ks_key, {})
        
        if not full or not noks:
            continue
        
        full_class = full.get("classification", "")
        noks_class = noks.get("classification", "")
        
        full_buggy_findings = full.get("buggy_findings", [])
        noks_buggy_findings = noks.get("buggy_findings", [])
        
        full_buggy_verdicts = full.get("buggy_verdicts", [])
        noks_buggy_verdicts = noks.get("buggy_verdicts", [])
        
        # Case 1: Full=TP, -KS != TP
        if full_class == "TP" and noks_class != "TP":
            ks_differential.append(b)
        
        # Case 2: Full has more buggy findings
        elif len(full_buggy_findings) > len(noks_buggy_findings):
            full_finds_more_findings.append(b)
    
    print(f"Cases where Full=TP but -KS != TP: {len(ks_differential)}")
    for b in ks_differential:
        cfgs = b["configs"]
        full = cfgs[full_key]
        noks = cfgs[ks_key]
        bf = full.get("buggy_findings", [])
        nf = noks.get("buggy_findings", [])
        print(f"  {b['project']}/bug#{b['bug_id']}: Full={full['classification']}, -KS={noks['classification']}")
        print(f"    Full buggy findings ({len(bf)}): {[f['bug_type'] for f in bf[:8]]}")
        print(f"    -KS  buggy findings ({len(nf)}): {[f['bug_type'] for f in nf[:8]]}")
        # Show what bug types are unique to Full
        full_types = set(f['bug_type'] for f in bf)
        noks_types = set(f['bug_type'] for f in nf)
        unique_to_full = full_types - noks_types
        if unique_to_full:
            print(f"    Bug types ONLY in Full (from kitchensink): {unique_to_full}")
        print()
    
    print(f"\nCases where Full has more buggy findings (but same classification): {len(full_finds_more_findings)}")
    for b in full_finds_more_findings[:10]:
        cfgs = b["configs"]
        full = cfgs[full_key]
        noks = cfgs[ks_key]
        bf = full.get("buggy_findings", [])
        nf = noks.get("buggy_findings", [])
        full_types = set(f['bug_type'] for f in bf)
        noks_types = set(f['bug_type'] for f in nf)
        unique_to_full = full_types - noks_types
        if unique_to_full:
            print(f"  {b['project']}/bug#{b['bug_id']}: Full={full['classification']} ({len(bf)} findings), -KS={noks['classification']} ({len(nf)} findings)")
            print(f"    Bug types ONLY in Full: {unique_to_full}")

    # Overall classification comparison
    print("\n--- Classification comparison (Full vs -KS) ---")
    from collections import Counter
    pairs = Counter()
    for b in data:
        cfgs = b.get("configs", {})
        full = cfgs.get(full_key, {})
        noks = cfgs.get(ks_key, {})
        if full and noks:
            fc = full.get("classification", "?")
            nc = noks.get("classification", "?")
            pairs[(fc, nc)] += 1
    
    for (fc, nc), cnt in sorted(pairs.items(), key=lambda x: -x[1]):
        marker = " <<<" if fc == "TP" and nc != "TP" else ""
        print(f"  Full={fc:12s}  -KS={nc:12s}  count={cnt}{marker}")


if __name__ == "__main__":
    main()
