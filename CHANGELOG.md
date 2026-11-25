# Changelog

All notable changes to this project. This project adheres to semantic versioning.

## v0.2.3 — 2026-11-24

- Window: Intake folder takes in every file under a folder (recursively) as one revision
- Window: Check hash list compares the vault with an outside SHA-256 list (plain, sha256sum output
  or CSV) and lists what's present, missing, or in the vault but not on the list
- Window: a Sign journal tab to create an Ed25519 key, sign the custody journal, and verify a
  signature, optionally against an expected public key; it says when a genuine signature covers
  an earlier journal state
- Offscreen GUI tests that drive the real window
- Add a verified one-line Linux installer (`install.sh`)

## v0.2.2 — 2026-11-16

- Attach a CycloneDX SBOM to each release (covered by the signed checksums)

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
