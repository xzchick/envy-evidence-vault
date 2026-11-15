"""ENVY Evidence Vault: offline, encrypted copied-file intake with a hash-verified custody journal."""

__version__ = "0.2.1"
from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
