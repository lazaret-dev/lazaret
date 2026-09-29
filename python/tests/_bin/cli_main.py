"""Test launcher: behaves like the installed console script."""
import sys

from lazaret._cli import main

sys.exit(main())
