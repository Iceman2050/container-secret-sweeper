#!/usr/bin/env python3
"""
container-secret-sweeper: scan container image layers for leaked secrets,
WITHOUT needing the Dockerfile.

Input is either:
  * a `docker save` tarball (contains <layer-id>/layer.tar entries), or
  * a directory holding layer tarballs.

Every layer tar is walked; text files are scanned against a built-in
secret-pattern table. Binary files (null byte in the first 8 KiB) and files
larger than --max-file-size are skipped.

Each finding reports: layer id (short), file path inside the layer, pattern
name, and a REDACTED match (first characters + "...***") -- never the full
secret, because scan reports get pasted into tickets and CI logs.

Exit code: 1 if any finding, 0 if clean, 2 on usage/IO errors.
That makes it a drop-in CI gate: fail the image build when secrets leak in.

Stdlib only: tarfile, re, argparse.
"""

import argparse
import io
import json
import os
import re
import sys
import tarfile

# ---------------------------------------------------------------------------
# Secret pattern table: (name, compiled regex).
# These are deliberately conservative shapes for well-known secret formats
# plus generic assignment patterns. They are not exhaustive -- see README
# "What it does NOT do".
# ---------------------------------------------------------------------------
PATTERNS = [
    ("aws-access-key-id",
     re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("aws-secret-access-key",
     re.compile(r"(?i)\baws_secret_access_key\b\s*=\s*['\"]?[A-Za-z0-9/+=]{40}")),
    ("github-token",
     re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b")),
    ("stripe-secret-key",
     re.compile(r"\bsk_live_[A-Za-z0-9]{24,}\b")),
    ("openai-api-key",
     re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b")),
    ("slack-token",
     re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("sendgrid-api-key",
     re.compile(r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b")),
    ("google-api-key",
     re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("private-key-pem",
     re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----")),
    ("password-assignment",
     re.compile(r"(?i)\b(?:password|passwd|pwd)\s*[:=]\s*['\"][^'\"]{3,}['\"]")),
    ("generic-api-key-assignment",
     re.compile(r"(?i)\b(?:api[_-]?key|secret[_-]?key|access[_-]?token)"
                r"\s*[:=]\s*['\"][^'\"]{8,}['\"]")),
]

DEFAULT_MAX_FILE_SIZE = 2 * 1024 * 1024   # 2 MiB -- files bigger than this are skipped
BINARY_PROBE_BYTES = 8192                 # null byte within these first bytes => binary


def redact(match_text):
    """Redact a matched secret for safe display: first chars + '...***'.

    Multiline matches are reduced to their first line first, so a PEM block
    never leaks its body -- only the header prefix shows.
    """
    first_line = match_text.split("\n", 1)[0].strip()
    return first_line[:8] + "\u2026***"


def iter_layer_tars(path):
    """Yield (short_layer_id, tarfile) for every layer in the input.

    Accepts a `docker save` tarball or a directory of layer tarballs.
    """
    if os.path.isdir(path):
        for root, _dirs, files in os.walk(path):
            for fname in sorted(files):
                if not fname.endswith(".tar"):
                    continue
                full = os.path.join(root, fname)
                layer_id = os.path.basename(root) if root != path else os.path.splitext(fname)[0]
                yield layer_id[:12], tarfile.open(full, "r")
    else:
        with tarfile.open(path, "r") as outer:
            inner_tars = []
            for member in outer:
                if member.isfile() and member.name.endswith("layer.tar"):
                    layer_id = member.name.split("/")[0][:12]
                    fh = outer.extractfile(member)
                    inner_tars.append((layer_id, io.BytesIO(fh.read())))
        for layer_id, buf in inner_tars:
            yield layer_id, tarfile.open(fileobj=buf, mode="r")


def is_binary(data):
    return b"\x00" in data[:BINARY_PROBE_BYTES]


def scan_layer_tar(tar, layer_id, max_file_size):
    """Scan one layer tar. Returns (findings, files_scanned, files_skipped)."""
    findings = []
    scanned = 0
    skipped = 0
    for member in tar:
        if not member.isfile():
            continue
        if member.size > max_file_size:
            skipped += 1
            continue
        fh = tar.extractfile(member)
        if fh is None:
            skipped += 1
            continue
        data = fh.read()
        if is_binary(data):
            skipped += 1
            continue
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            skipped += 1
            continue
        scanned += 1
        for pattern_name, rx in PATTERNS:
            for m in rx.finditer(text):
                findings.append({
                    "layer": layer_id,
                    "file": "/" + member.name.lstrip("./"),
                    "pattern": pattern_name,
                    "match": redact(m.group(0)),
                })
    return findings, scanned, skipped


def scan_image(path, max_file_size=DEFAULT_MAX_FILE_SIZE):
    """Scan every layer of the image. Returns (findings, stats)."""
    all_findings = []
    stats = {"layers": 0, "files_scanned": 0, "files_skipped": 0}
    for layer_id, tar in iter_layer_tars(path):
        stats["layers"] += 1
        try:
            findings, scanned, skipped = scan_layer_tar(tar, layer_id, max_file_size)
        finally:
            tar.close()
        all_findings.extend(findings)
        stats["files_scanned"] += scanned
        stats["files_skipped"] += skipped
    return all_findings, stats


def format_text(findings, stats, path):
    lines = []
    for f in findings:
        lines.append("[!] %-24s layer=%-12s file=%-32s match=%s"
                     % (f["pattern"], f["layer"], f["file"], f["match"]))
    lines.append("")
    lines.append("scanned %s: %d layer(s), %d file(s) scanned, %d skipped (binary/too large)"
                 % (path, stats["layers"], stats["files_scanned"], stats["files_skipped"]))
    if findings:
        lines.append("RESULT: %d secret finding(s) -- FAIL" % len(findings))
    else:
        lines.append("RESULT: clean -- no secrets found")
    return "\n".join(lines)


def make_demo_tarball(path="demo-image.tar"):
    """Build a small fixture `docker save`-style tarball and return its path.

    Layer a1b2c3d4e5f6 contains a planted (fake) AWS key in /app/config.py
    and a fake PEM block in /root/.ssh/id_rsa. Layer d4e5f6a1b2c3 is clean.
    Used by the 30-second quickstart: --make-demo builds it, then scans it.
    """
    fake_key = "AKIAIOSFODNN7EXAMPLE"  # AWS docs example key -- not real
    config_py = (
        "# demo config\n"
        'AWS_ACCESS_KEY_ID = "%s"\n'
        'AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"\n'
        % fake_key
    )
    fake_pem = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIFakeKeyForDemoPurposesOnlyDoNotUseInProduction1234567890\n"
        "-----END RSA PRIVATE KEY-----\n"
    )
    clean_sh = "#!/bin/sh\necho hello\n"

    def make_layer(files):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as t:
            for arcname, content in files.items():
                data = content.encode("utf-8")
                info = tarfile.TarInfo(name=arcname)
                info.size = len(data)
                info.mode = 0o644
                t.addfile(info, io.BytesIO(data))
        buf.seek(0)
        return buf.read()

    layer1 = make_layer({"app/config.py": config_py, "root/.ssh/id_rsa": fake_pem})
    layer2 = make_layer({"usr/local/bin/entrypoint.sh": clean_sh})

    with tarfile.open(path, "w") as outer:
        for layer_id, layer_data in (("a1b2c3d4e5f6", layer1),
                                     ("d4e5f6a1b2c3", layer2)):
            info = tarfile.TarInfo(name="%s/layer.tar" % layer_id)
            info.size = len(layer_data)
            outer.addfile(info, io.BytesIO(layer_data))
        manifest = json.dumps([{
            "Config": "config.json",
            "RepoTags": ["demo:latest"],
            "Layers": ["a1b2c3d4e5f6/layer.tar", "d4e5f6a1b2c3/layer.tar"],
        }]).encode("utf-8")
        info = tarfile.TarInfo(name="manifest.json")
        info.size = len(manifest)
        outer.addfile(info, io.BytesIO(manifest))
    return path


def build_parser():
    p = argparse.ArgumentParser(
        description="Scan container image layers for leaked secrets. "
                    "Exit 1 on any finding (CI gate)."
    )
    p.add_argument("image", nargs="?",
                   help="`docker save` tarball, or a directory of layer tarballs")
    p.add_argument("--max-file-size", type=int, default=DEFAULT_MAX_FILE_SIZE,
                   help="skip files larger than this many bytes (default: %(default)s)")
    p.add_argument("--json", action="store_true",
                   help="emit findings as JSON instead of text")
    p.add_argument("--make-demo", action="store_true",
                   help="build a demo image tarball with planted (fake) secrets and scan it")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)

    if args.make_demo:
        demo_path = make_demo_tarball()
        print("demo image tarball written to %s" % demo_path)
        args.image = demo_path

    if not args.image:
        print("error: give me an image tarball, a layer directory, or --make-demo",
              file=sys.stderr)
        return 2
    if not os.path.exists(args.image):
        print("error: not found: %s" % args.image, file=sys.stderr)
        return 2

    try:
        findings, stats = scan_image(args.image, args.max_file_size)
    except (tarfile.TarError, OSError) as exc:
        print("error: cannot read %s: %s" % (args.image, exc), file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps({"image": args.image, "stats": stats,
                          "findings": findings}, indent=2))
    else:
        print(format_text(findings, stats, args.image))
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
