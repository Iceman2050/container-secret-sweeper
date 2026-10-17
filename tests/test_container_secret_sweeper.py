"""Tests for container_secret_sweeper.

Builds fixture image tarballs in the test itself (no Docker needed):
  * a two-layer image -- layer 1 plants a fake AWS key in /app/config.py and
    a fake PEM block in /root/.ssh/id_rsa; layer 2 is clean
  * a fully clean single-layer image

Asserts findings carry correct layer/file attribution and redacted values,
and that a clean image yields a clean report (exit 0) while a dirty image
exits 1.
"""

import io
import json
import os
import sys
import tarfile
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import container_secret_sweeper as css  # noqa: E402

FAKE_AWS_KEY = "AKIAIOSFODNN7EXAMPLE"  # AWS documentation example key -- not real
FAKE_PEM = ("-----BEGIN RSA PRIVATE KEY-----\n"
            "MIIFakeKeyForTestPurposesOnly1234567890\n"
            "-----END RSA PRIVATE KEY-----\n")


def make_layer_tar(files):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as t:
        for arcname, content in files.items():
            data = content if isinstance(content, bytes) else content.encode("utf-8")
            info = tarfile.TarInfo(name=arcname)
            info.size = len(data)
            t.addfile(info, io.BytesIO(data))
    buf.seek(0)
    return buf.read()


def make_image_tarball(path, layers):
    """layers: list of (layer_id, {arcname: content}). docker-save style."""
    with tarfile.open(path, "w") as outer:
        for layer_id, files in layers:
            layer_data = make_layer_tar(files)
            info = tarfile.TarInfo(name="%s/layer.tar" % layer_id)
            info.size = len(layer_data)
            outer.addfile(info, io.BytesIO(layer_data))


class TestContainerSecretSweeper(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dirty = os.path.join(self.tmp.name, "dirty.tar")
        make_image_tarball(self.dirty, [
            ("a1b2c3d4e5f6a1b2c3d4",
             {"app/config.py": 'AWS_KEY = "%s"\n' % FAKE_AWS_KEY,
              "root/.ssh/id_rsa": FAKE_PEM}),
            ("d4e5f6a1b2c3d4e5f6a1",
             {"usr/local/bin/run.sh": "#!/bin/sh\necho ok\n"}),
        ])
        self.clean = os.path.join(self.tmp.name, "clean.tar")
        make_image_tarball(self.clean, [
            ("cafef00d1234abcd5678",
             {"app/main.py": "print('hello')\n",
              "app/data.bin": b"\x00\x01\x02binary\xff"}),
        ])

    def tearDown(self):
        self.tmp.cleanup()

    def test_dirty_image_finds_both_secrets_with_attribution(self):
        findings, stats = css.scan_image(self.dirty)
        by_pattern = {f["pattern"]: f for f in findings}
        self.assertIn("aws-access-key-id", by_pattern)
        self.assertIn("private-key-pem", by_pattern)
        self.assertEqual(stats["layers"], 2)

        aws = by_pattern["aws-access-key-id"]
        self.assertEqual(aws["layer"], "a1b2c3d4e5f6")   # short id, 12 chars
        self.assertEqual(aws["file"], "/app/config.py")
        self.assertNotIn(FAKE_AWS_KEY, aws["match"])       # redacted, never full secret
        self.assertTrue(aws["match"].endswith("\u2026***"))

        pem = by_pattern["private-key-pem"]
        self.assertEqual(pem["layer"], "a1b2c3d4e5f6")
        self.assertEqual(pem["file"], "/root/.ssh/id_rsa")
        self.assertNotIn("MIIFakeKey", pem["match"])

    def test_clean_layer_produces_no_findings(self):
        findings, _stats = css.scan_image(self.clean)
        clean_only = [f for f in findings if f["layer"] == "cafef00d1234"]
        self.assertEqual(clean_only, [])

    def test_clean_image_scans_silent(self):
        findings, stats = css.scan_image(self.clean)
        self.assertEqual(findings, [])
        self.assertEqual(stats["layers"], 1)

    def test_binary_files_are_skipped(self):
        findings, stats = css.scan_image(self.clean)
        self.assertEqual(findings, [])
        self.assertGreaterEqual(stats["files_skipped"], 1)  # data.bin

    def test_exit_code_1_on_findings_0_when_clean(self):
        self.assertEqual(css.main([self.dirty]), 1)
        self.assertEqual(css.main([self.clean]), 0)

    def test_directory_of_layer_tars_input(self):
        layer_dir = os.path.join(self.tmp.name, "layers")
        os.makedirs(os.path.join(layer_dir, "a1b2c3d4e5f6"))
        with open(os.path.join(layer_dir, "a1b2c3d4e5f6", "layer.tar"), "wb") as fh:
            fh.write(make_layer_tar({"secrets.env": 'GITHUB_TOKEN="ghp_' + "x" * 36 + '"\n'}))
        findings, stats = css.scan_image(layer_dir)
        self.assertEqual(stats["layers"], 1)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["pattern"], "github-token")
        self.assertNotIn("ghp_" + "x" * 36, findings[0]["match"])

    def test_make_demo_builds_and_scans_dirty(self):
        cwd = os.getcwd()
        os.chdir(self.tmp.name)
        try:
            rc = css.main(["--make-demo"])
        finally:
            os.chdir(cwd)
        self.assertEqual(rc, 1)
        self.assertTrue(os.path.exists(os.path.join(self.tmp.name, "demo-image.tar")))
        findings, _stats = css.scan_image(os.path.join(self.tmp.name, "demo-image.tar"))
        patterns = {f["pattern"] for f in findings}
        self.assertIn("aws-access-key-id", patterns)
        self.assertIn("private-key-pem", patterns)

    def test_password_assignment_pattern(self):
        path = os.path.join(self.tmp.name, "pw.tar")
        make_image_tarball(path, [
            ("bbbbccccddddeeeeffff",
             {"app/settings.ini": 'password = "hunter2hunter"\n'}),
        ])
        findings, _stats = css.scan_image(path)
        pw = [f for f in findings if f["pattern"] == "password-assignment"]
        self.assertEqual(len(pw), 1)
        self.assertNotIn("hunter2hunter", pw[0]["match"])


if __name__ == "__main__":
    unittest.main()
