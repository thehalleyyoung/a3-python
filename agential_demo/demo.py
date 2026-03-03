from pathlib import Path
import sys
import traceback

# Ensure workspace root is on sys.path so local `a3_python` package is importable
workspace_root = Path(__file__).resolve().parents[1]
if str(workspace_root) not in sys.path:
    sys.path.insert(0, str(workspace_root))

def main():
    try:
        from a3_python.analyzer import Analyzer
        target = Path(__file__).parent / "target.py"
        print(f"Analyzing target: {target}")
        analyzer = Analyzer(verbose=True, timeout_ms=1000, max_paths=50)
        result = analyzer.analyze_file(target)
        print("--- Analysis Result Summary ---")
        print(result.summary())
    except Exception as e:
        print("Error running demo:")
        traceback.print_exc()

if __name__ == '__main__':
    main()
