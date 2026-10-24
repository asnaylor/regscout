"""Allow running regscout via `python3 -m regscout`."""

import sys
from regscout.cli import main

if __name__ == "__main__":
    sys.exit(main())
