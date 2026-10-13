"""
Test suite. Run it with `python -m tests` (or unittest discovery with
`-t .`), so this runs first: log files go to a temporary folder, not into
logs/ of the install the tests run on.
"""

import os
import tempfile

os.environ.setdefault('LAZYEASM_LOG_DIR', tempfile.mkdtemp(prefix='lazyeasm-test-logs-'))
