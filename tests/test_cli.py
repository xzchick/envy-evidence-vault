"""CLI tests that need no display. The passphrase prompt is patched."""

import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from envy_evidence_vault import cli


class CLITest(unittest.TestCase):
    SECRET = b"a long private evidence passphrase"

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="envy-evidence-cli-"))
        self.addCleanup(__import__("shutil").rmtree, self.dir)

    def invoke(self, *args, secret=None):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err), \
                mock.patch.object(cli, "_passphrase", return_value=secret or self.SECRET):
            code = cli.main([str(a) for a in args])
        return code, out.getvalue(), err.getvalue()

    def test_version(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), self.assertRaises(SystemExit) as ctx:
            cli.main(["--version"])
        self.assertEqual(ctx.exception.code, 0)
        self.assertIn("envy-evidence-vault", out.getvalue())

    def test_new_intake_verify_flow(self):
        vault = self.dir / "vault"
        code, out, _ = self.invoke("new", vault, "--title", "Case 7")
        self.assertEqual(code, 0)
        self.assertTrue((vault / "manifest.evault").exists())

        src = self.dir / "photo.jpg"
        src.write_bytes(b"a photograph")
        code, out, _ = self.invoke("intake", vault, src, "--custodian", "Raven")
        self.assertEqual(code, 0)
        self.assertIn("intake:", out)

        code, out, _ = self.invoke("verify", vault)
        self.assertEqual(code, 0)
        self.assertIn("1 verified", out)

    def test_verify_nonzero_on_missing(self):
        vault = self.dir / "v2"
        self.invoke("new", vault, "--title", "Case")
        src = self.dir / "f"
        src.write_bytes(b"data")
        self.invoke("intake", vault, src)
        # Remove the object so verification reports missing and exits non-zero.
        for obj in (vault / "objects").glob("*.evobj"):
            obj.unlink()
        code, out, _ = self.invoke("verify", vault, "--no-record")
        self.assertEqual(code, 1)
        self.assertIn("1 missing", out)

    def test_inspect_and_export(self):
        vault = self.dir / "v3"
        self.invoke("new", vault, "--title", "Case")
        src = self.dir / "doc.txt"
        src.write_bytes(b"document")
        self.invoke("intake", vault, src)
        code, out, _ = self.invoke("inspect", vault)
        self.assertEqual(code, 0)
        report = json.loads(out)
        self.assertEqual(report["evidence"][0]["filename"], "doc.txt")
        out_html = self.dir / "r.html"
        code, out, _ = self.invoke("export", vault, out_html, "--format", "html")
        self.assertEqual(code, 0)
        self.assertIn("sha256", out)
        self.assertTrue(out_html.exists())

    def test_transfer_and_note(self):
        vault = self.dir / "v4"
        self.invoke("new", vault, "--title", "Case")
        code, _, _ = self.invoke("transfer", vault, "--custodian", "Wren")
        self.assertEqual(code, 0)
        code, _, _ = self.invoke("note", vault, "--title", "Sealed")
        self.assertEqual(code, 0)

    def test_bad_passphrase_is_error(self):
        vault = self.dir / "v5"
        self.invoke("new", vault, "--title", "Case")
        code, _, err = self.invoke("inspect", vault, secret=b"the wrong passphrase!")
        self.assertEqual(code, 2)
        self.assertIn("passphrase", err.lower())

    def test_unknown_command(self):
        with self.assertRaises(SystemExit):
            cli.build_parser().parse_args(["seance"])


if __name__ == "__main__":
    unittest.main()
