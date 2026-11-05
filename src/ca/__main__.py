"""Allow `python -m ca`."""

from ca.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
