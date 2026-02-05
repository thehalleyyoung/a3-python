#!/bin/bash
# Wait 20 minutes, then report results

echo "=================================================================="
echo "ULTRA-AGGRESSIVE FP REDUCTION - 20 MINUTE CHECKPOINT"
echo "=================================================================="
echo "Started: $(date)"
echo "Will report at: $(date -v+20M 2>/dev/null || date -d '+20 minutes' 2>/dev/null || echo 'in 20 minutes')"
echo ""
echo "Analysis running with PyTorch contracts and 5 strategies..."
echo "=================================================================="
echo ""

# Wait 20 minutes
sleep 1200

echo ""
echo "=================================================================="
echo "20 MINUTES ELAPSED - RESULTS"
echo "=================================================================="
echo ""

# Check if analysis completed
if [ -f "/Users/halleyyoung/Documents/PythonFromScratch/results/ultra_aggressive_results.txt" ]; then
    echo "✓ Analysis COMPLETED"
    echo ""
    cat /Users/halleyyoung/Documents/PythonFromScratch/results/ultra_aggressive_results.txt
else
    echo "⏳ Analysis still running or incomplete"
    echo ""
    echo "Current log tail:"
    tail -50 /Users/halleyyoung/Documents/PythonFromScratch/results/ultra_aggressive_full.log 2>/dev/null || echo "No log yet"
fi

echo ""
echo "=================================================================="
echo "Full log: results/ultra_aggressive_full.log"
echo "Results: results/ultra_aggressive_results.txt"
echo "=================================================================="
