from __future__ import print_function

import sys

from . import cli

rc = 1
try:
    cli.main()
    rc = 0
except Exception as e:
    print('Error: %s' % e, file=sys.stderr)
sys.exit(rc)
