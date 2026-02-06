"""
Allow running pyfromscratch as a module:

    python3.11 -m pyfromscratch <target> [options]

Delegates to pyfromscratch.cli:main().
"""
import sys
from .cli import main

sys.exit(main())
