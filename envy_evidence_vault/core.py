"""Encrypted evidence vaults: copied-file intake, a hash-chained custody journal,
and verification that each collected file is unchanged since intake.

A self-contained engine for the ENVY BLACK VEIL Evidence Vault, packaged as a
standalone app. A vault is a directory holding an encrypted, revision-preserving
*manifest* and an *objects* store. Intaking a file copies it into the store,
encrypted at rest, keyed by the SHA-256 of its original bytes; that fingerprint
is recorded in the manifest. Verification decrypts each stored object and
re-hashes it, proving the bytes are unchanged since intake.

Honest by design: a hash proves a file is unchanged since intake — not where it
came from, who made it, or that it is genuine. Custodian labels and timestamps
are operator assertions, not identities or trusted facts. The encrypted envelope
is the same AES-256-GCM used by ENVY Vault.

Standard library only, apart from ``cryptography`` for the encrypted envelope.
"""

from __future__ import annotations

import datetime
import hashlib
import csv
import html
import io
import json
import os
import re
import stat
import uuid
from pathlib import Path

# --- Shared errors and bounds ------------------------------------------------

MAGIC = b"ENVYVAULT2\x00"
MAX_ENVELOPE = 8 * 1024 * 1024            # the manifest
MAX_OBJECT = 256 * 1024 * 1024           # a single intaken evidence file
MAX_RECORDS = 5000
MIN_PASSPHRASE = 12
KINDS = ("intake", "verification", "transfer", "note")
MANIFEST_NAME = "manifest.evault"
OBJECTS_DIR = "objects"


class EvidenceError(RuntimeError):
    """A clean, expected error: a bad passphrase, an invalid record, a chain mismatch."""


# --- Safe file primitives (never follow symlinks, never overwrite) -----------

def read_regular(path, limit: int = MAX_ENVELOPE) -> bytes:
    path = Path(path).expanduser()
    fd = os.open(str(path), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    with os.fdopen(fd, "rb") as stream:
        meta = os.fstat(stream.fileno())
        if not stat.S_ISREG(meta.st_mode) or meta.st_size > limit:
            raise EvidenceError("Expected a regular file within the size limit")
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise EvidenceError("File exceeded the size limit")
    return data


def new_file(path, data: bytes, mode: int = 0o600) -> Path:
    """Write a brand-new file. O_EXCL means an existing file is never overwritten."""
    path = Path(path).expanduser()
    try:
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    except FileExistsError:
        raise EvidenceError(f"Refusing to overwrite an existing file: {path}") from None
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    return path


def _replace_file(path, data: bytes, mode: int = 0o600) -> Path:
    """Atomically write the manifest in place (write temp, fsync, rename)."""
    path = Path(path).expanduser()
    tmp = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(tmp, path)
    return path


# --- Encrypted envelope (byte-compatible with ENVY Vault) --------------------

def _key(secret: bytes, salt: bytes) -> bytes:
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    return Scrypt(salt=salt, length=32, n=2 ** 15, r=8, p=1).derive(secret)


def encrypt_bytes(data: bytes, secret: bytes) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    salt, nonce = os.urandom(16), os.urandom(12)
    return MAGIC + salt + nonce + AESGCM(_key(secret, salt)).encrypt(nonce, data, MAGIC)


def decrypt_bytes(data: bytes, secret: bytes) -> bytes:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    if not data.startswith(MAGIC) or len(data) < len(MAGIC) + 44:
        raise EvidenceError("Not an ENVY encrypted envelope")
    blob = data[len(MAGIC):]
    try:
        return AESGCM(_key(secret, blob[:16])).decrypt(blob[16:28], blob[28:], MAGIC)
    except InvalidTag:
        raise EvidenceError("Incorrect passphrase or modified encrypted data") from None


def check_passphrase(secret: bytes) -> bytes:
    if not isinstance(secret, (bytes, bytearray)) or len(secret) < MIN_PASSPHRASE:
        raise EvidenceError(f"Use a passphrase of at least {MIN_PASSPHRASE} bytes")
    return bytes(secret)


# --- Canonical form and field validation -------------------------------------

def _canonical(value) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _utc() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _text(value, field, limit, required=True):
    if not isinstance(value, str) or len(value) > limit or "\x00" in value or (required and not value.strip()):
        raise EvidenceError("Invalid manifest record " + field)
    try:
        value.encode("utf-8")
    except UnicodeError:
        raise EvidenceError("Manifest record " + field + " must contain valid Unicode text") from None
    return value


def _timestamp(value, field="recorded_utc"):
    _text(value, field, 64)
    try:
        parsed = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise EvidenceError(field + " must be ISO 8601 with a UTC offset") from None
    if parsed.tzinfo is None or parsed.utcoffset() != datetime.timedelta(0):
        raise EvidenceError(field + " must be expressed in UTC (+00:00 or Z)")
    return parsed.isoformat()


def _sha256_field(value, field):
    if not isinstance(value, str) or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
        raise EvidenceError(field + " must be 64 lowercase hexadecimal characters")
    return value


def _validate_record(value, objects=()):
    """Validate one content record. ``objects`` is the set of known object SHA-256s."""
    known = set(objects)
    if not isinstance(value, dict) or value.get("kind") not in KINDS:
        raise EvidenceError("Manifest record kind must be one of: " + ", ".join(KINDS))
    kind = value["kind"]
    allowed = {"kind", "title", "note", "custodian", "object_sha256", "filename",
               "size", "source_path", "result"}
    if set(value) - allowed:
        raise EvidenceError("Unknown manifest record field")

    record = {"kind": kind, "title": _text(value.get("title"), "title", 300),
              "note": _text(value.get("note", ""), "note", 32000, required=False)}

    if "custodian" in value and value["custodian"] != "":
        record["custodian"] = _text(value["custodian"], "custodian", 200)

    if kind == "intake":
        record["object_sha256"] = _sha256_field(value.get("object_sha256"), "object_sha256")
        record["filename"] = _text(value.get("filename"), "filename", 500)
        size = value.get("size")
        if type(size) is not int or not 0 <= size <= MAX_OBJECT:
            raise EvidenceError("Intake size must be an integer within the object limit")
        record["size"] = size
        record["source_path"] = _text(value.get("source_path", ""), "source path", 4096, required=False)
    else:
        for forbidden in ("object_sha256", "filename", "size", "source_path"):
            if value.get(forbidden):
                raise EvidenceError("Only intake records describe a stored object")

    if kind == "verification":
        result = value.get("result")
        if not isinstance(result, dict) or set(result) - {"verified", "mismatch", "missing", "object_sha256"}:
            raise EvidenceError("A verification record needs a result summary")
        summary = {}
        for key in ("verified", "mismatch", "missing"):
            count = result.get(key, 0)
            if type(count) is not int or count < 0:
                raise EvidenceError("Verification counts must be non-negative integers")
            summary[key] = count
        refs = result.get("object_sha256", [])
        if not isinstance(refs, list) or any(r not in known for r in (_sha256_field(x, "object_sha256") for x in refs)):
            raise EvidenceError("Verification must reference known object fingerprints")
        summary["object_sha256"] = list(refs)
        record["result"] = summary
    elif "result" in value:
        raise EvidenceError("Only verification records carry a result")
    return record


def _validate_manifest(data):
    fields = {"schema", "vault_id", "title", "created_utc", "revision",
              "previous_envelope_sha256", "records"}
    if not isinstance(data, dict) or set(data) != fields or type(data["schema"]) is not int or data["schema"] != 1:
        raise EvidenceError("Unsupported encrypted manifest schema")
    _text(data["title"], "vault title", 200)
    try:
        uuid.UUID(data["vault_id"])
    except (ValueError, TypeError, AttributeError):
        raise EvidenceError("Invalid vault identifier") from None
    _timestamp(data["created_utc"], "created_utc")
    records = data["records"]
    if not isinstance(records, list) or len(records) > MAX_RECORDS or type(data["revision"]) is not int or data["revision"] != len(records):
        raise EvidenceError("Invalid manifest revision or record count")
    if not isinstance(data["previous_envelope_sha256"], str) or len(data["previous_envelope_sha256"]) != 64 \
            or any(c not in "0123456789abcdef" for c in data["previous_envelope_sha256"]):
        raise EvidenceError("Invalid previous encrypted revision digest")
    previous, ids, objects = "0" * 64, set(), set()
    for record in records:
        meta = {"id", "recorded_utc", "previous_sha256", "record_sha256"}
        if not isinstance(record, dict) or not meta <= set(record):
            raise EvidenceError("Invalid journal metadata")
        try:
            uuid.UUID(record["id"])
        except (ValueError, TypeError, AttributeError):
            raise EvidenceError("Invalid record identifier") from None
        if record["id"] in ids:
            raise EvidenceError("Duplicate record identifier")
        _timestamp(record["recorded_utc"])
        content = {k: v for k, v in record.items() if k not in meta}
        normalized = _validate_record(content, objects)
        if normalized != content:
            raise EvidenceError("Encrypted manifest record is incomplete or not normalized")
        core = {k: v for k, v in record.items() if k != "record_sha256"}
        if record["previous_sha256"] != previous or hashlib.sha256(_canonical(core)).hexdigest() != record["record_sha256"]:
            raise EvidenceError("Manifest journal hash chain mismatch")
        previous = record["record_sha256"]
        ids.add(record["id"])
        if record["kind"] == "intake":
            objects.add(record["object_sha256"])
    return data


# --- Vault layout ------------------------------------------------------------

def _manifest_path(vault):
    return Path(vault).expanduser() / MANIFEST_NAME


def _objects_dir(vault):
    return Path(vault).expanduser() / OBJECTS_DIR


def _object_path(vault, object_sha256):
    return _objects_dir(vault) / (object_sha256 + ".evobj")


def _load(vault, secret):
    encrypted = read_regular(_manifest_path(vault), MAX_ENVELOPE)
    try:
        data = json.loads(decrypt_bytes(encrypted, secret))
    except (json.JSONDecodeError, UnicodeError, RecursionError):
        raise EvidenceError("Encrypted manifest does not contain valid JSON") from None
    return _validate_manifest(data), hashlib.sha256(encrypted).hexdigest()


def _save(vault, data, secret):
    check_passphrase(secret)
    encoded = _canonical(_validate_manifest(data))
    if len(encoded) + 128 > MAX_ENVELOPE:
        raise EvidenceError("Manifest exceeds the 8 MiB encrypted limit")
    _replace_file(_manifest_path(vault), encrypt_bytes(encoded, secret))


def create(vault, title, secret):
    check_passphrase(secret)
    vault = Path(vault).expanduser()
    if vault.exists() and any(vault.iterdir()):
        raise EvidenceError("Refusing to create a vault in a non-empty directory")
    vault.mkdir(parents=True, exist_ok=True)
    _objects_dir(vault).mkdir(exist_ok=True)
    data = {"schema": 1, "vault_id": str(uuid.uuid4()), "title": _text(title, "vault title", 200),
            "created_utc": _utc(), "revision": 0, "previous_envelope_sha256": "0" * 64, "records": []}
    # The manifest does not exist yet, so create it with O_EXCL for a genuine first write.
    new_file(_manifest_path(vault), encrypt_bytes(_canonical(data), secret))
    return {"vault": str(vault), "vault_id": data["vault_id"], "revision": 0}


def _append(vault, data, previous_envelope, value, secret):
    if len(data["records"]) >= MAX_RECORDS:
        raise EvidenceError(f"Manifest has reached its {MAX_RECORDS} record limit")
    objects = {r["object_sha256"] for r in data["records"] if r["kind"] == "intake"}
    record = _validate_record(value, objects)
    record.update(id=str(uuid.uuid4()), recorded_utc=_utc(),
                  previous_sha256=data["records"][-1]["record_sha256"] if data["records"] else "0" * 64)
    record["record_sha256"] = hashlib.sha256(_canonical(record)).hexdigest()
    data["records"].append(record)
    data["revision"] += 1
    data["previous_envelope_sha256"] = previous_envelope
    _save(vault, data, secret)
    return record


# --- Intake, verify, custody -------------------------------------------------

def intake(vault, source, secret, custodian="", note=""):
    """Copy a file into the vault, encrypted at rest, and record its fingerprint."""
    payload = read_regular(source, MAX_OBJECT)
    object_sha256 = hashlib.sha256(payload).hexdigest()
    data, envelope = _load(vault, secret)
    object_path = _object_path(vault, object_sha256)
    duplicate = object_path.exists()
    if not duplicate:
        new_file(object_path, encrypt_bytes(payload, secret))
    value = {"kind": "intake", "title": Path(source).name or "evidence",
             "object_sha256": object_sha256, "filename": Path(source).name or "evidence",
             "size": len(payload), "source_path": str(Path(source).expanduser())}
    if custodian:
        value["custodian"] = custodian
    if note:
        value["note"] = note
    record = _append(vault, data, envelope, value, secret)
    return {"vault": str(vault), "object_sha256": object_sha256, "size": len(payload),
            "duplicate_object": duplicate, "revision": data["revision"], "record_id": record["id"]}


def _verify_object(vault, object_sha256, size, secret):
    object_path = _object_path(vault, object_sha256)
    if not object_path.exists():
        return "missing"
    try:
        stored = decrypt_bytes(read_regular(object_path, MAX_OBJECT + 1024), secret)
    except EvidenceError:
        return "mismatch"
    if len(stored) != size or hashlib.sha256(stored).hexdigest() != object_sha256:
        return "mismatch"
    return "verified"


def verify(vault, secret, record_result=True):
    """Re-hash every stored object and report integrity. Optionally log the result."""
    data, envelope = _load(vault, secret)
    latest = {}
    for record in data["records"]:
        if record["kind"] == "intake":
            latest[record["object_sha256"]] = record
    results, counts = [], {"verified": 0, "mismatch": 0, "missing": 0}
    for sha, record in latest.items():
        status = _verify_object(vault, sha, record["size"], secret)
        counts[status] += 1
        results.append({"object_sha256": sha, "filename": record["filename"],
                        "size": record["size"], "status": status})
    summary = {"vault": str(vault), "checked": len(results), **counts, "objects": results,
               "basis": "Each stored object was decrypted and re-hashed. A match proves the bytes are "
                        "unchanged since intake — not their origin or authenticity."}
    if record_result and results:
        value = {"kind": "verification",
                 "title": f"Verified {counts['verified']}/{len(results)} objects",
                 "result": {k: counts[k] for k in ("verified", "mismatch", "missing")}}
        value["result"]["object_sha256"] = [r["object_sha256"] for r in results]
        record = _append(vault, data, envelope, value, secret)
        summary["revision"] = data["revision"]
        summary["record_id"] = record["id"]
    return summary


def transfer(vault, secret, custodian, note=""):
    data, envelope = _load(vault, secret)
    value = {"kind": "transfer", "title": f"Custody to {custodian}", "custodian": custodian}
    if note:
        value["note"] = note
    record = _append(vault, data, envelope, value, secret)
    return {"vault": str(vault), "revision": data["revision"], "record_id": record["id"]}


def note(vault, secret, title, body="", custodian=""):
    data, envelope = _load(vault, secret)
    value = {"kind": "note", "title": title}
    if body:
        value["note"] = body
    if custodian:
        value["custodian"] = custodian
    record = _append(vault, data, envelope, value, secret)
    return {"vault": str(vault), "revision": data["revision"], "record_id": record["id"]}


# --- Views -------------------------------------------------------------------

def evidence(data):
    """The current evidence list, folding later verifications onto each object."""
    _validate_manifest(data)
    items, last_status = {}, {}
    for record in data["records"]:
        if record["kind"] == "verification":
            for sha in record["result"]["object_sha256"]:
                last_status[sha] = record["recorded_utc"]
    for record in data["records"]:
        if record["kind"] == "intake":
            sha = record["object_sha256"]
            items.setdefault(sha, {"object_sha256": sha, "filename": record["filename"],
                                   "size": record["size"], "custodian": record.get("custodian", ""),
                                   "intake_utc": record["recorded_utc"],
                                   "source_path": record.get("source_path", ""),
                                   "last_verified_utc": last_status.get(sha, "")})
    return list(items.values())


_HASH_RE = re.compile(r"[0-9a-fA-F]{64}")


def _parse_hash_list(lines):
    """Pull the SHA-256 digests out of a list of text lines. Forgiving of format:
    plain one-per-line, `sha256sum` output (hash then filename), or a CSV with a
    hash column all work — any 64-hex token on a line is taken, others skipped."""
    digests = []
    for raw in lines:
        match = _HASH_RE.search(raw)
        if match:
            digests.append(match.group(0).lower())
    return digests


def verify_against_list(vault, secret, expected):
    """Reconcile the vault's intaken objects against an expected list of SHA-256
    digests. Read-only, and it compares *identities* — which expected files were
    taken in, which are absent, and which vault objects are not on the list. It
    does not re-hash the stored bytes; run verify() for that.

    `expected` is an iterable of text lines (see _parse_hash_list).
    """
    data, _ = _load(vault, secret)
    names = {e["object_sha256"]: e["filename"] for e in evidence(data)}
    in_vault = set(names)
    want, seen = [], set()
    for digest in _parse_hash_list(expected):
        if digest not in seen:
            seen.add(digest); want.append(digest)
    present = [{"object_sha256": h, "filename": names[h]} for h in want if h in in_vault]
    missing = [h for h in want if h not in in_vault]
    extra = [{"object_sha256": h, "filename": names[h]} for h in sorted(in_vault - seen)]
    return {"vault": str(vault), "expected": len(want), "in_vault": len(in_vault),
            "present": present, "missing": missing, "extra": extra,
            "match": not missing and not extra,
            "basis": "Compares SHA-256 identities only: which expected files were taken in, which are "
                     "absent, and which vault objects are not on the list. It does not re-hash the stored "
                     "bytes — run verify for that — and a digest proves integrity, not provenance."}


def custody_log(data):
    _validate_manifest(data)
    return [{"id": r["id"], "kind": r["kind"], "title": r["title"], "recorded_utc": r["recorded_utc"],
             "custodian": r.get("custodian", ""), "note": r.get("note", ""),
             "object_sha256": r.get("object_sha256", ""), "filename": r.get("filename", ""),
             "size": r.get("size", ""), "result": r.get("result", "")} for r in data["records"]]


def inspect(vault, secret):
    data, envelope = _load(vault, secret)
    return {"vault_id": data["vault_id"], "title": data["title"], "revision": data["revision"],
            "created_utc": data["created_utc"], "envelope_sha256": envelope,
            "evidence": evidence(data), "custody_log": custody_log(data),
            "warning": "Hashes verify integrity only. Custodian labels and timestamps are operator "
                       "assertions, not identities or trusted facts."}


def inspect_vault(vault, secret):
    return inspect(vault, secret)


# --- Plaintext export --------------------------------------------------------

def export(vault, destination, secret, format="html"):
    if format not in ("html", "json", "csv"):
        raise EvidenceError("Export format must be html, json or csv")
    data, envelope = _load(vault, secret)
    items, log = evidence(data), custody_log(data)
    report = {"vault": {"vault_id": data["vault_id"], "title": data["title"],
                        "created_utc": data["created_utc"], "revision": data["revision"]},
              "evidence": items, "custody_log": log, "envelope_sha256": envelope,
              "limitations": "Plaintext export. A matching hash proves a file is unchanged since intake, "
                             "not its origin, authorship, or authenticity. Custodian labels and timestamps "
                             "are operator assertions, and the hash chain does not establish a trusted time."}
    if format == "json":
        output = (json.dumps(report, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    elif format == "csv":
        def _safe(value):
            # Prefix a leading =,+,-,@ so a spreadsheet cannot treat a field as a formula.
            text = str(value)
            return "'" + text if text[:1] in ("=", "+", "-", "@") else text

        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(["filename", "object_sha256", "size", "custodian",
                         "intake_utc", "last_verified_utc", "source_path"])
        for item in items:
            writer.writerow([_safe(item["filename"]), item["object_sha256"], item["size"],
                             _safe(item["custodian"]), item["intake_utc"],
                             item["last_verified_utc"] or "", _safe(item.get("source_path", ""))])
        output = buf.getvalue().encode("utf-8")
    else:
        def esc(value):
            return html.escape(str(value), quote=True)

        rows = ""
        for item in items:
            rows += ("<tr><td>" + esc(item["filename"]) + "</td><td><code>" + esc(item["object_sha256"]) +
                     "</code></td><td>" + esc(item["size"]) + "</td><td>" + esc(item["custodian"]) +
                     "</td><td>" + esc(item["intake_utc"]) + "</td><td>" +
                     esc(item["last_verified_utc"] or "not verified") + "</td></tr>")
        events = ""
        for entry in log:
            extra = esc(entry["result"]) if entry["result"] else esc(entry["note"])
            events += ("<tr><td>" + esc(entry["recorded_utc"]) + "</td><td>" + esc(entry["kind"]) +
                       "</td><td>" + esc(entry["title"]) + "</td><td>" + esc(entry["custodian"]) +
                       "</td><td>" + extra + "</td></tr>")
        # No external content, executable script, clickable operator-supplied URLs, or active HTML.
        output = ("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
                  "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'\">"
                  "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
                  "<title>" + esc(data["title"]) + "</title><style>body{max-width:72rem;margin:2rem auto;padding:0 1rem;font:16px system-ui;line-height:1.5}"
                  "table{border-collapse:collapse;width:100%;margin:0 0 2rem}th,td{border:1px solid #777;padding:.4rem .6rem;text-align:left;vertical-align:top}"
                  "th{background:#eee}code{word-break:break-all;font-size:.85em}</style></head><body><h1>" + esc(data["title"]) +
                  "</h1><p>" + esc(report["limitations"]) + "</p><p>Vault: " + esc(data["vault_id"]) +
                  " · Revision: " + str(data["revision"]) + " · Encrypted manifest SHA-256: " + envelope +
                  "</p><h2>Evidence</h2><table><thead><tr><th>File</th><th>SHA-256 (original bytes)</th><th>Size</th>"
                  "<th>Custodian</th><th>Intake UTC</th><th>Last verified</th></tr></thead><tbody>" + rows +
                  "</tbody></table><h2>Custody log</h2><table><thead><tr><th>UTC</th><th>Event</th><th>Title</th>"
                  "<th>Custodian</th><th>Detail</th></tr></thead><tbody>" + events +
                  "</tbody></table></body></html>").encode("utf-8")
    new_file(destination, output)
    return {"output": str(destination), "format": format, "plaintext": True,
            "sha256": hashlib.sha256(output).hexdigest(), "evidence_count": len(items)}
