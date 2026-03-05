#!/usr/bin/env python3.11
"""One-shot script: find opcodes used in the synthetic suite but not handled in symbolic_vm.py."""
import re
from pathlib import Path

vm_path = Path("a3_python/semantics/symbolic_vm.py")
text = vm_path.read_text()

handled = set()
for m in re.finditer(r'opname\s*==\s*"(\w+)"', text):
    handled.add(m.group(1))
for m in re.finditer(r"opname\s*==\s*'(\w+)'", text):
    handled.add(m.group(1))
# Also catch `opname in [...]` or `opname in {...}`
for m in re.finditer(r'opname\s+in\s+[\[{]([^\]{}]+)[\]}]', text):
    block = m.group(1)
    for om in re.finditer(r'"(\w+)"', block):
        handled.add(om.group(1))
    for om in re.finditer(r"'(\w+)'", block):
        handled.add(om.group(1))

import dis
suite = Path("tests/synthetic_suite")
needed = set()
for pyfile in sorted(suite.rglob("*.py")):
    try:
        code = compile(pyfile.read_text(), str(pyfile), "exec")
        worklist = [code]
        while worklist:
            co = worklist.pop()
            for instr in dis.get_instructions(co):
                needed.add(instr.opname)
            for const in co.co_consts:
                if hasattr(const, "co_code"):
                    worklist.append(const)
    except Exception:
        pass

missing = sorted(needed - handled)
print(f"Handled: {len(handled)} | Needed: {len(needed)} | Missing: {len(missing)}")
for op in missing:
    print(f"  {op}")
