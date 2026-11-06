"""ENVY Evidence Vault: offline, encrypted copied-file intake with a hash-verified custody journal."""

__version__ = "0.1.0"
from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
