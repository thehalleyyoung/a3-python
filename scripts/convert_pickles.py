#!/usr/bin/env python3
"""Convert pickle result files to readable JSON."""
import pickle
import json
import pathlib

out_dir = pathlib.Path("results/new_msft_batch_full_analysis")
for pkl in sorted(out_dir.glob("*.json")):
    if pkl.name.endswith(".readable.json"):
        continue
    # Try pickle first, then JSON
    try:
        with open(pkl, "rb") as f:
            data = pickle.load(f)
    except Exception:
        try:
            with open(pkl, "r") as f:
                data = json.load(f)
        except Exception as e:
            print(f"SKIP {pkl.name}: {e}")
            continue
    json_data = {
        "project": data["project"],
        "total_functions": data["total_functions"],
        "total_bugs": data["total_bugs"],
        "fully_guarded": data["fully_guarded"],
        "barrier_proven_fp": data["barrier_proven_fp"],
        "grand_fp": data["grand_fp"],
        "remaining_count": data["remaining_count"],
        "remaining": [[str(fn), str(bt)] for fn, bt in data["remaining"]],
        "dse_reachable": {
            str(k): [str(v[0]), str(v[1])] for k, v in data["dse_reachable"].items()
        },
        "dse_unreachable": [str(x) for x in data["dse_unreachable"]],
        "prod_bugs": [[str(fn), str(bt)] for fn, bt in data["prod_bugs"]],
        "test_bugs": [[str(fn), str(bt)] for fn, bt in data["test_bugs"]],
    }
    json_path = pkl.with_suffix(".readable.json")
    with open(json_path, "w") as f:
        json.dump(json_data, f, indent=2)
    print(f"{pkl.name} -> {json_path.name}: {len(data['prod_bugs'])} prod bugs")
