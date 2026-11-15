# Changelog

All notable changes to this project. This project adheres to semantic versioning.

## v0.2.1 — 2026-11-15

- Sign release checksums with Sigstore (keyless) and attach the `.sigstore.json` bundle
- Add property/fuzz hardening tests for the AES-256-GCM + scrypt envelope

## v0.2.0 — 2026-11-14

- Add an optional Ed25519 signature over the custody journal
- Add Markdown export of a vault
- Add bulk intake: take in a whole folder in one revision
- Add verify-against-list: reconcile a vault with an expected hash list
- Add CSV custody manifest export
- Show object count and total size in the window header
- Docs: point install at the live v0.1.0 release

## v0.1.0

- Initial public release.
