#!/usr/bin/env python3
"""Debug why DIV_ZERO is detected as PANIC"""

import sys
sys.path.insert(0, '/Users/halleyyoung/Documents/PythonFromScratch')

from pathlib import Path
from pyfromscratch.semantics.symbolic_vm import SymbolicVM
from pyfromscratch.unsafe.registry import check_unsafe_regions, UNSAFE_PREDICATES
import types
import z3

# Load position.py and extract _buy_stock
filepath = Path('external_tools/Qlib/qlib/backtest/position.py')
with open(filepath, 'r') as f:
    source = f.read()
module_code = compile(source, str(filepath), 'exec')

# Find Position class, then _buy_stock method
for const in module_code.co_consts:
    if isinstance(const, types.CodeType) and const.co_name == 'Position':
        # This is the class - look for methods inside
        for method in const.co_consts:
            if isinstance(method, types.CodeType) and method.co_name == '_buy_stock':
                print(f'Found _buy_stock: {method}')
                print(f'Args: {method.co_varnames[:method.co_argcount]}')
                
                # Try symbolic execution with mock self
                vm = SymbolicVM(verbose=False)
                initial_path = vm.load_code(method)
                
                # Initialize self with a mock position dict
                if initial_path.state.frame_stack:
                    frame = initial_path.state.frame_stack[-1]
                    # Mock self as object with position dict
                    class MockPosition:
                        def __init__(self):
                            self.position = {'cash': 1000.0}
                    frame.locals['self'] = MockPosition()
                    # Leave trade_price as symbolic (could be 0)
                    frame.locals['trade_price'] = z3.Real('trade_price')
                    frame.locals['trade_val'] = z3.Real('trade_val')
                    frame.locals['cost'] = z3.Real('cost')
                    frame.locals['stock_id'] = 'TEST'
                
                # Step until halted
                paths = [initial_path]
                for i in range(50):
                    if not paths:
                        print(f'No paths at step {i}')
                        break
                    p = paths[0]
                    if p.state.halted:
                        print(f'Halted at step {i}')
                        print(f'  exception = {p.state.exception}')
                        
                        # Check if div_by_zero_reached is set
                        if hasattr(p.state, 'div_by_zero_reached'):
                            print(f'  div_by_zero_reached = {p.state.div_by_zero_reached}')
                        
                        # Check each unsafe predicate
                        print('\nChecking each unsafe predicate:')
                        for bug_type, (predicate, extractor) in UNSAFE_PREDICATES.items():
                            try:
                                if predicate(p.state):
                                    print(f'  {bug_type}: TRUE')
                            except Exception as e:
                                pass
                        break
                    try:
                        new_paths = vm.step(p)
                        paths = new_paths
                    except Exception as e:
                        print(f'Error at step {i}: {type(e).__name__}: {e}')
                        break
                break
        break
