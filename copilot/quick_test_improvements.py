#!/usr/bin/env python3
"""
Quick test of improved false positive reduction strategies.
Tests the regex patterns directly without full CrashSummary objects.
"""
import re

def test_safe_idiom_patterns():
    """Test the regex patterns for safe idioms"""
    
    print("=" * 80)
    print("TESTING SAFE IDIOM DETECTION PATTERNS")
    print("=" * 80)
    
    # Pattern 1: max(x, epsilon) where epsilon > 0
    max_pattern = re.compile(r'max\s*\([^,]+,\s*([0-9.e-]+)\s*\)', re.IGNORECASE)
    
    # Pattern 2: abs(x) + constant where constant > 0
    abs_pattern = re.compile(r'abs\s*\([^)]+\)\s*\+\s*([0-9.e-]+)', re.IGNORECASE)
    
    # Pattern 3: x or fallback where fallback != 0
    or_pattern = re.compile(r'\w+\s+or\s+([0-9.e-]+)', re.IGNORECASE)
    
    # Pattern 4: division by numeric constant
    const_div_pattern = re.compile(r'/\s*([0-9]+)', re.IGNORECASE)
    
    # Pattern 5: len(x) + positive
    len_pattern = re.compile(r'len\s*\([^)]+\)\s*\+\s*([0-9]+)', re.IGNORECASE)
    
    test_cases = [
        # (code, pattern, pattern_name, should_match, epsilon_should_be_safe)
        ("result = x / max(y, 1e-9)", max_pattern, "max(y, epsilon)", True, True),
        ("result = x / max(y, 0.001)", max_pattern, "max(y, epsilon)", True, True),
        ("result = x / max(y, 0)", max_pattern, "max(y, epsilon)", True, False),  # matches but epsilon=0
        ("result = x / (abs(y) + 1e-8)", abs_pattern, "abs(y) + constant", True, True),
        ("result = x / (abs(y) + 0)", abs_pattern, "abs(y) + constant", True, False),
        ("result = x / (y or 1)", or_pattern, "x or fallback", True, True),
        ("result = x / (y or 0)", or_pattern, "x or fallback", True, False),
        ("result = x / 32", const_div_pattern, "/ constant", True, True),
        ("result = x / (len(items) + 1)", len_pattern, "len(x) + positive", True, True),
        ("result = x / len(items)", len_pattern, "len(x) + positive", False, False),
    ]
    
    passed = 0
    failed = 0
    
    for code, pattern, pattern_name, should_match, epsilon_safe in test_cases:
        match = pattern.search(code)
        matched = match is not None
        
        # Check if epsilon/constant is safe (> 0)
        is_safe = False
        if matched and match.groups():
            try:
                value = float(match.group(1))
                is_safe = value > 0
            except:
                is_safe = False
        
        # Overall result
        correct_match = (matched == should_match)
        correct_safety = (not matched or is_safe == epsilon_safe)
        overall_correct = correct_match and correct_safety
        
        status = "✅ PASS" if overall_correct else "❌ FAIL"
        
        print(f"\n{status}: {pattern_name}")
        print(f"  Code: {code}")
        print(f"  Expected match: {should_match}, Got: {matched}")
        if matched and match.groups():
            print(f"  Extracted value: {match.group(1)}, Safe: {is_safe} (expected {epsilon_safe})")
        
        if overall_correct:
            passed += 1
        else:
            failed += 1
    
    print("\n" + "=" * 80)
    print(f"Results: {passed} passed, {failed} failed")
    print("=" * 80)
    
    return passed, failed

def test_alignment_detection():
    """Test alignment constant detection heuristics"""
    
    print("\n" + "=" * 80)
    print("TESTING ALIGNMENT CONSTANT DETECTION")
    print("=" * 80)
    
    test_cases = [
        # (function_name, var_name, should_be_alignment)
        ("_read_buffer_aligned", "alignment", True),
        ("get_alignment", "chunk_size", True),
        ("io_buffer_size", "alignment", True),
        ("dnvme_read", "align_size", True),
        ("compute_loss", "batch_size", False),
        ("train_step", "learning_rate", False),
    ]
    
    passed = 0
    failed = 0
    
    alignment_keywords_func = ['buffer', 'alignment', 'align', 'io', 'dnvme']
    alignment_keywords_var = ['align', 'size', 'chunk']
    
    for func_name, var_name, should_detect in test_cases:
        func_has_keyword = any(kw in func_name.lower() for kw in alignment_keywords_func)
        var_has_keyword = any(kw in var_name.lower() for kw in alignment_keywords_var)
        
        detected = func_has_keyword and var_has_keyword
        
        status = "✅ PASS" if detected == should_detect else "❌ FAIL"
        
        print(f"\n{status}: {func_name}.{var_name}")
        print(f"  Expected: {should_detect}, Got: {detected}")
        print(f"  Function keyword: {func_has_keyword}, Var keyword: {var_has_keyword}")
        
        if detected == should_detect:
            passed += 1
        else:
            failed += 1
    
    print("\n" + "=" * 80)
    print(f"Results: {passed} passed, {failed} failed")
    print("=" * 80)
    
    return passed, failed

if __name__ == "__main__":
    p1, f1 = test_safe_idiom_patterns()
    p2, f2 = test_alignment_detection()
    
    total_passed = p1 + p2
    total_failed = f1 + f2
    
    print("\n" + "=" * 80)
    print("OVERALL RESULTS")
    print("=" * 80)
    print(f"Total: {total_passed} passed, {total_failed} failed")
    print(f"Success rate: {100 * total_passed / (total_passed + total_failed):.1f}%")
    print("=" * 80)
