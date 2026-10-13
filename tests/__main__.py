"""Run the whole suite: python -m tests [-v]"""

import os
import sys
import unittest

import tests  # noqa: F401  (sets the temporary log folder before anything else is imported)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

if __name__ == '__main__':
    suite = unittest.defaultTestLoader.discover(os.path.join(ROOT, 'tests'), pattern='*_tests.py', top_level_dir=ROOT)
    result = unittest.TextTestRunner(verbosity=2 if '-v' in sys.argv else 1).run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
