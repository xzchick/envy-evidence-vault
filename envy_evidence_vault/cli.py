"""Command-line entry point. The Evidence Vault window is the default.

Intake copies a file into the vault; the manifest and objects are never silently
overwritten, and the custody journal is append-only.
"""

from __future__ import annotations

import argparse
import getpass
import json
import sys

from . import __version__
from .core import (EvidenceError, check_passphrase, create, export, inspect,
                   intake, note, transfer, verify)


def build_parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(
        prog="envy-evidence-vault",
        description="Offline, encrypted evidence vaults: copied-file intake, a hash-chained custody "
                    "journal, and verification that each file is unchanged since intake. Run with no "
                    "arguments to open the window. Local only: no network, no accounts.")
    root.add_argument("--version", action="version", version=f"envy-evidence-vault {__version__}")
    commands = root.add_subparsers(dest="command")
    commands.add_parser("gui", help="open the Evidence Vault window (default)")

    new = commands.add_parser("new", help="create a new encrypted vault directory")
    new.add_argument("vault", help="a new, empty directory for the vault")
    new.add_argument("--title", required=True, help="the vault / case title")

    take = commands.add_parser("intake", help="copy a file into the vault and record its fingerprint")
    take.add_argument("vault")
    take.add_argument("source", help="the file to intake")
    take.add_argument("--custodian", default="", help="an optional custodian label")
    take.add_argument("--note", default="", help="an optional note")

    ver = commands.add_parser("verify", help="re-hash every stored object and log the result")
    ver.add_argument("vault")
    ver.add_argument("--no-record", action="store_true", help="check without writing a verification record")

    tr = commands.add_parser("transfer", help="record a custody transfer (a label, not an identity)")
    tr.add_argument("vault")
    tr.add_argument("--custodian", required=True)
    tr.add_argument("--note", default="")

    nt = commands.add_parser("note", help="record a note in the custody journal")
    nt.add_argument("vault")
    nt.add_argument("--title", required=True)
    nt.add_argument("--body", default="")
    nt.add_argument("--custodian", default="")

    insp = commands.add_parser("inspect", help="print the decrypted manifest (read-only)")
    insp.add_argument("vault")

    exp = commands.add_parser("export", help="write a plaintext HTML or JSON report")
    exp.add_argument("vault")
    exp.add_argument("destination", help="a new report file; never overwritten")
    exp.add_argument("--format", default="html", choices=("html", "json"))
    return root


def _passphrase(confirm: bool = False) -> bytes:
    if not sys.stdin.isatty():
        raise EvidenceError("Open this action in a terminal so the passphrase is not echoed")
    value = getpass.getpass("Vault passphrase: ").encode()
    if confirm and value != getpass.getpass("Repeat passphrase: ").encode():
        raise EvidenceError("Passphrases do not match")
    return check_passphrase(value)


def _run(args) -> int:
    if args.command == "new":
        result = create(args.vault, args.title, _passphrase(confirm=True))
        print(f"new vault: {result['vault']} (revision {result['revision']})")
        return 0
    if args.command == "intake":
        result = intake(args.vault, args.source, _passphrase(), args.custodian, args.note)
        dup = " (duplicate object, referenced)" if result["duplicate_object"] else ""
        print(f"intake: {result['object_sha256']}  {result['size']} bytes{dup} → revision {result['revision']}")
        return 0
    if args.command == "verify":
        result = verify(args.vault, _passphrase(), record_result=not args.no_record)
        print(f"verify: {result['verified']} verified, {result['mismatch']} mismatch, "
              f"{result['missing']} missing (of {result['checked']})")
        return 0 if result["mismatch"] == 0 and result["missing"] == 0 else 1
    if args.command == "transfer":
        result = transfer(args.vault, _passphrase(), args.custodian, args.note)
        print(f"transfer recorded → revision {result['revision']}")
        return 0
    if args.command == "note":
        result = note(args.vault, _passphrase(), args.title, args.body, args.custodian)
        print(f"note recorded → revision {result['revision']}")
        return 0
    if args.command == "export":
        result = export(args.vault, args.destination, _passphrase(), args.format)
        print(f"export ({result['format']}): wrote {result['output']}  sha256 {result['sha256']}")
        return 0
    if args.command == "inspect":
        print(json.dumps(inspect(args.vault, _passphrase()), indent=2, ensure_ascii=False))
        return 0
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command in (None, "gui"):
        from .gui import run_app
        return run_app()
    try:
        return _run(args)
    except EvidenceError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\nCancelled.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
