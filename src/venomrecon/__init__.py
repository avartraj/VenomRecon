"""VenomRecon package.

The original project used direct imports such as ``from core import logger``
when run as ``python src/venomrecon/main.py``. Keep the package directory on
``sys.path`` so installed entry points remain compatible while modules are
gradually migrated to absolute package imports.
"""

import os
import sys

_PKG_DIR = os.path.dirname(os.path.abspath(__file__))
if _PKG_DIR not in sys.path:
    sys.path.insert(0, _PKG_DIR)
