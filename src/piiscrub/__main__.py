import sys

# Absolute import (not `from .cli`): this module is PyInstaller's frozen entry
# point and runs as top-level `__main__` with no parent package, where a
# relative import fails. Absolute import works both here and under
# `python -m piiscrub` (where piiscrub is on the path).
from piiscrub.cli import main

if __name__ == "__main__":
    sys.exit(main())
