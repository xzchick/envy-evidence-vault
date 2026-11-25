"""Offscreen GUI tests: drive the real ENVY Evidence Vault window without a display."""
import hashlib
import os
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

try:
    import PyQt6.QtWidgets  # noqa: F401
    HAVE_QT = True
except Exception:  # pragma: no cover - PyQt6 missing
    HAVE_QT = False

from envy_evidence_vault import core

SECRET = b"a long private evidence passphrase"


@unittest.skipUnless(HAVE_QT, "PyQt6 is not installed")
class EvidenceWindowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from envy_evidence_vault.gui import _build
        app_cls, cls.Window = _build()
        cls.app = app_cls.instance() or app_cls([])

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.case = self.root / "case"
        (self.case / "photos").mkdir(parents=True)
        (self.case / "statement.txt").write_text("statement")
        (self.case / "photos" / "a.jpg").write_bytes(b"jpeg-a")
        (self.case / "photos" / "copy.jpg").write_bytes(b"jpeg-a")   # same bytes: one object
        self.vault = self.root / "vault"
        core.create(self.vault, "Case 7", SECRET)
        self.w = self.Window()
        self.warnings = []
        self.w._warn = lambda message, icon=None, title="Evidence Vault": self.warnings.append(message)
        self.w._open_path(self.vault, SECRET)

    def tearDown(self):
        self.w.timer.stop()
        self.w.close()
        self.tmp.cleanup()

    def cells(self, table, col):
        return [table.item(r, col).text() for r in range(table.rowCount()) if table.item(r, col)]

    def test_intake_folder_takes_every_file_in_one_revision(self):
        before = self.w.data["revision"]
        result = self.w.intake_folder_values(str(self.case), "J. Doe", "seized drive")
        self.assertEqual(result["intaken"], 3)
        self.assertEqual(sum(i["duplicate_object"] for i in result["items"]), 1)
        self.assertEqual(self.w.data["revision"], before + 3)
        self.assertEqual(self.w.t_evidence.rowCount(), 2)   # two distinct objects

    def test_hash_list_shows_present_missing_and_extra(self):
        self.w.intake_folder_values(str(self.case))
        want = hashlib.sha256(b"statement").hexdigest()
        absent = "f" * 64
        listing = self.root / "expected.sha256"
        listing.write_text(f"{want}  statement.txt\n{absent}  lost.bin\nnot a hash line\n")
        result = self.w.check_hash_list_file(str(listing))
        self.assertFalse(result["match"])
        self.assertEqual(sorted(self.cells(self.w.t_list, 0)), ["missing", "not on list", "present"])
        self.assertIn("1 present, 1 missing, 1 in the vault but not on the list", self.w.vault_header.toPlainText())

    def test_sign_then_verify_and_detect_a_changed_journal(self):
        self.w.intake_folder_values(str(self.case))
        key = self.w.make_signing_key(str(self.root / "me.key"))
        self.assertIn(key["public_key"], self.w.s_status.text())
        sig = self.root / "journal.sig.json"
        self.assertIsNotNone(self.w.sign_with(str(self.root / "me.key"), str(sig)))
        self.w.s_pubkey.setText(key["public_key"])
        self.assertTrue(self.w.verify_signature(str(sig))["valid"])
        self.assertTrue(self.w.s_status.text().startswith("Valid"))
        self.w.s_pubkey.setText("00" * 32)                      # a different expected signer
        self.assertFalse(self.w.verify_signature(str(sig))["valid"])
        self.assertIn("different key", self.w.s_status.text())
        self.w.s_pubkey.setText("")
        core.note(self.vault, SECRET, "later note")              # the journal moves on
        self.w.data, _ = core._load(self.vault, SECRET)
        result = self.w.verify_signature(str(sig))
        self.assertTrue(result["signature_ok"])
        self.assertFalse(result["valid"])
        self.assertIn("earlier journal state", self.w.s_status.text())


if __name__ == "__main__":
    unittest.main()
