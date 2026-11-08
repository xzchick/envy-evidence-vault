"""Core Evidence Vault tests: encrypted manifest round trips, the journal hash
chain, copied-file intake into the object store, verification (verified / mismatch
/ missing), custody events, export and the no-overwrite guarantee.
"""

import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from envy_evidence_vault import core
from envy_evidence_vault.core import EvidenceError


class EvidenceTest(unittest.TestCase):
    SECRET = b"a long private evidence passphrase"

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="envy-evidence-"))
        self.addCleanup(__import__("shutil").rmtree, self.dir)
        self.src = self.dir / "src"
        self.src.mkdir()

    def make_vault(self, name="vault", title="Case"):
        path = self.dir / name
        core.create(path, title, self.SECRET)
        return path

    def source_file(self, name, content):
        p = self.src / name
        p.write_bytes(content)
        return p

    # ----- envelope -----------------------------------------------------
    def test_encrypted_round_trip_and_magic(self):
        blob = core.encrypt_bytes(b"evidence", self.SECRET)
        self.assertTrue(blob.startswith(core.MAGIC))
        self.assertEqual(core.decrypt_bytes(blob, self.SECRET), b"evidence")
        self.assertEqual(blob[:11], b"ENVYVAULT2\x00")  # byte-compatible with ENVY Vault

    def test_short_passphrase_rejected(self):
        with self.assertRaises(EvidenceError):
            core.create(self.dir / "short", "Case", b"tooshort")

    # ----- create -------------------------------------------------------
    def test_create_lays_out_vault(self):
        vault = self.make_vault(title="Night shift")
        self.assertTrue((vault / core.MANIFEST_NAME).exists())
        self.assertTrue((vault / core.OBJECTS_DIR).is_dir())
        data, _ = core._load(vault, self.SECRET)
        self.assertEqual(data["revision"], 0)
        self.assertEqual(data["title"], "Night shift")

    def test_refuses_non_empty_directory(self):
        busy = self.dir / "busy"
        busy.mkdir()
        (busy / "something").write_text("x")
        with self.assertRaises(EvidenceError):
            core.create(busy, "Case", self.SECRET)

    # ----- intake -------------------------------------------------------
    def test_intake_copies_encrypts_and_records(self):
        vault = self.make_vault()
        payload = b"photograph bytes " * 100
        src = self.source_file("photo.jpg", payload)
        result = core.intake(vault, src, self.SECRET, custodian="Raven", note="From the shelf")
        self.assertEqual(result["object_sha256"], hashlib.sha256(payload).hexdigest())
        self.assertEqual(result["size"], len(payload))
        self.assertFalse(result["duplicate_object"])
        # The stored object is encrypted at rest (not the raw bytes).
        stored = (vault / core.OBJECTS_DIR / (result["object_sha256"] + ".evobj")).read_bytes()
        self.assertTrue(stored.startswith(core.MAGIC))
        self.assertNotIn(payload, stored)
        self.assertEqual(core.decrypt_bytes(stored, self.SECRET), payload)
        data, _ = core._load(vault, self.SECRET)
        self.assertEqual(data["records"][0]["kind"], "intake")
        self.assertEqual(data["records"][0]["custodian"], "Raven")

    def test_duplicate_intake_dedupes_object(self):
        vault = self.make_vault()
        payload = b"same bytes"
        a = core.intake(vault, self.source_file("a", payload), self.SECRET)
        b = core.intake(vault, self.source_file("b", payload), self.SECRET)
        self.assertEqual(a["object_sha256"], b["object_sha256"])
        self.assertTrue(b["duplicate_object"])
        objects = list((vault / core.OBJECTS_DIR).glob("*.evobj"))
        self.assertEqual(len(objects), 1)  # one object, two intake records
        data, _ = core._load(vault, self.SECRET)
        self.assertEqual(len([r for r in data["records"] if r["kind"] == "intake"]), 2)

    def test_intake_chains_the_journal(self):
        vault = self.make_vault()
        core.intake(vault, self.source_file("a", b"aaaa"), self.SECRET)
        core.intake(vault, self.source_file("b", b"bbbb"), self.SECRET)
        data, _ = core._load(vault, self.SECRET)
        self.assertEqual(data["records"][1]["previous_sha256"], data["records"][0]["record_sha256"])
        self.assertEqual(data["revision"], 2)

    # ----- verify -------------------------------------------------------
    def test_verify_all_good(self):
        vault = self.make_vault()
        core.intake(vault, self.source_file("a", b"alpha"), self.SECRET)
        core.intake(vault, self.source_file("b", b"beta!"), self.SECRET)
        result = core.verify(vault, self.SECRET)
        self.assertEqual((result["verified"], result["mismatch"], result["missing"]), (2, 0, 0))
        # Verification is logged as a record.
        data, _ = core._load(vault, self.SECRET)
        self.assertEqual(data["records"][-1]["kind"], "verification")

    def test_verify_detects_tampered_object(self):
        vault = self.make_vault()
        r = core.intake(vault, self.source_file("a", b"original bytes"), self.SECRET)
        obj = vault / core.OBJECTS_DIR / (r["object_sha256"] + ".evobj")
        obj.write_bytes(core.encrypt_bytes(b"tampered bytes!", self.SECRET))  # re-encrypt different content
        result = core.verify(vault, self.SECRET, record_result=False)
        self.assertEqual((result["verified"], result["mismatch"], result["missing"]), (0, 1, 0))

    def test_verify_detects_missing_object(self):
        vault = self.make_vault()
        r = core.intake(vault, self.source_file("a", b"present then gone"), self.SECRET)
        (vault / core.OBJECTS_DIR / (r["object_sha256"] + ".evobj")).unlink()
        result = core.verify(vault, self.SECRET, record_result=False)
        self.assertEqual((result["verified"], result["mismatch"], result["missing"]), (0, 0, 1))

    def test_verify_no_record_leaves_revision(self):
        vault = self.make_vault()
        core.intake(vault, self.source_file("a", b"x"), self.SECRET)
        before, _ = core._load(vault, self.SECRET)
        core.verify(vault, self.SECRET, record_result=False)
        after, _ = core._load(vault, self.SECRET)
        self.assertEqual(before["revision"], after["revision"])

    # ----- tamper detection on the manifest ----------------------------
    def test_tampered_manifest_breaks_chain(self):
        vault = self.make_vault()
        core.intake(vault, self.source_file("a", b"x"), self.SECRET)
        data, _ = core._load(vault, self.SECRET)
        data["records"][0]["title"] = "Forged"
        (vault / core.MANIFEST_NAME).write_bytes(core.encrypt_bytes(core._canonical(data), self.SECRET))
        with self.assertRaises(EvidenceError):
            core.inspect(vault, self.SECRET)

    # ----- custody events ----------------------------------------------
    def test_transfer_and_note_recorded(self):
        vault = self.make_vault()
        core.transfer(vault, self.SECRET, "Wren", note="Handed to lab")
        core.note(vault, self.SECRET, "Sealed bag", body="Tag 44")
        log = core.custody_log(core._load(vault, self.SECRET)[0])
        kinds = [e["kind"] for e in log]
        self.assertEqual(kinds, ["transfer", "note"])
        self.assertEqual(log[0]["custodian"], "Wren")

    def test_last_verified_shows_in_evidence_view(self):
        vault = self.make_vault()
        core.intake(vault, self.source_file("a", b"x"), self.SECRET)
        core.verify(vault, self.SECRET)
        items = core.evidence(core._load(vault, self.SECRET)[0])
        self.assertTrue(items[0]["last_verified_utc"])

    # ----- export -------------------------------------------------------
    def test_export_html_and_json(self):
        vault = self.make_vault()
        core.intake(vault, self.source_file("photo.jpg", b"bytes"), self.SECRET, custodian="Raven")
        html_out = self.dir / "r.html"
        res = core.export(vault, html_out, self.SECRET, "html")
        text = html_out.read_text()
        self.assertEqual(res["format"], "html")
        self.assertIn("Content-Security-Policy", text)
        self.assertIn("photo.jpg", text)
        json_out = self.dir / "r.json"
        core.export(vault, json_out, self.SECRET, "json")
        report = json.loads(json_out.read_text())
        self.assertEqual(report["vault"]["revision"], 1)
        self.assertIn("limitations", report)

    def test_export_csv_manifest(self):
        import csv as _csv
        vault = self.make_vault()
        core.intake(vault, self.source_file("a.jpg", b"img"), self.SECRET, custodian="Raven")
        out = self.dir / "manifest.csv"
        res = core.export(vault, out, self.SECRET, "csv")
        self.assertEqual(res["format"], "csv")
        rows = list(_csv.reader(out.read_text().splitlines()))
        self.assertEqual(rows[0][:4], ["filename", "object_sha256", "size", "custodian"])
        self.assertEqual(rows[1][0], "a.jpg")
        self.assertEqual(rows[1][3], "Raven")

    def test_csv_guards_formula_injection(self):
        vault = self.make_vault()
        core.intake(vault, self.source_file("b.jpg", b"x"), self.SECRET, custodian="=SUM(A1)")
        out = self.dir / "m.csv"
        core.export(vault, out, self.SECRET, "csv")
        self.assertIn("'=SUM(A1)", out.read_text())

    def test_export_escapes_markup(self):
        # Operator-supplied text (here a custodian label) must be HTML-escaped. The label
        # carries the markup rather than the filename, since some filesystems reject "<>".
        vault = self.make_vault()
        core.intake(vault, self.source_file("photo.jpg", b"x"), self.SECRET, custodian="<script>alert(1)</script>")
        out = self.dir / "r.html"
        core.export(vault, out, self.SECRET, "html")
        body = out.read_text()
        self.assertNotIn("<script>alert(1)</script>", body)
        self.assertIn("&lt;script&gt;", body)

    # ----- no overwrite -------------------------------------------------
    def test_new_file_never_overwrites(self):
        keep = self.dir / "keep"
        keep.write_bytes(b"precious")
        with self.assertRaises(EvidenceError):
            core.new_file(keep, b"clobber")
        self.assertEqual(keep.read_bytes(), b"precious")

    def test_export_refuses_to_overwrite(self):
        vault = self.make_vault()
        dest = self.dir / "exists.html"
        dest.write_bytes(b"keep me")
        with self.assertRaises(EvidenceError):
            core.export(vault, dest, self.SECRET, "html")
        self.assertEqual(dest.read_bytes(), b"keep me")


if __name__ == "__main__":
    unittest.main()
