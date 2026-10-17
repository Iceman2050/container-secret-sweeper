# container-secret-sweeper

Secrets leak into container images constantly — an AWS key baked into `/app/config.py`, a private key left in `/root/.ssh/`, a Stripe key in an env file. The Dockerfile won't tell you: the secret arrived in a `COPY`, a build-arg default, or a base layer you didn't write. By the time the image hits a registry, the secret is one `docker pull` away from anyone.

**container-secret-sweeper** scans every layer of a container image for leaked secrets — **no Dockerfile needed**. Point it at a `docker save` tarball (or a directory of layer tarballs), and it reports exactly which layer and which file each secret came from. Exit code 1 on any finding, so it drops straight into your image-build pipeline as a CI gate.

## 30-second quickstart

```bash
# Generate a demo image tarball (with planted FAKE secrets) and scan it:
python container_secret_sweeper.py --make-demo

# Scan a real image:
docker save myapp:latest -o myapp.tar
python container_secret_sweeper.py myapp.tar
```

## Example output

Real run below — the `--make-demo` quickstart, captured verbatim from the tool (the planted secrets are AWS's own published example values, not real credentials):

```
$ python container_secret_sweeper.py --make-demo
demo image tarball written to demo-image.tar
[!] aws-access-key-id        layer=a1b2c3d4e5f6 file=/app/config.py                   match=AKIAIOSF…***
[!] aws-secret-access-key    layer=a1b2c3d4e5f6 file=/app/config.py                   match=AWS_SECR…***
[!] private-key-pem          layer=a1b2c3d4e5f6 file=/root/.ssh/id_rsa                match=-----BEG…***

scanned demo-image.tar: 2 layer(s), 3 file(s) scanned, 0 skipped (binary/too large)
RESULT: 3 secret finding(s) -- FAIL
```

(exit code 1 — the build would be stopped here.)

A clean image reports silence and exits 0:

```
$ python container_secret_sweeper.py clean-image.tar

scanned clean-image.tar: 1 layer(s), 1 file(s) scanned, 0 skipped (binary/too large)
RESULT: clean -- no secrets found
```

Every finding shows the **short layer id**, the **file path inside the layer**, the **pattern name**, and a **redacted match** (`prefix…***`) — the full secret never appears in the report, because scan output gets pasted into tickets and CI logs.

## How it works

1. Opens the `docker save` tarball, finds every `<layer-id>/layer.tar` inside (or walks a directory of layer tars).
2. Reads each file in each layer: skips binaries (null byte in the first 8 KiB) and files over `--max-file-size` (default 2 MiB).
3. Scans text against a built-in table of 11 patterns: AWS access key IDs, AWS secret access keys, GitHub tokens, Stripe live keys, OpenAI keys, Slack tokens, SendGrid keys, Google API keys, PEM private-key blocks, `password = "..."` assignments, and generic `api_key`/`secret`/`access_token` assignments.
4. Prints findings, a scan summary, and exits 1 if anything matched.

`--json` emits the same report as JSON for pipeline consumption.

## What it does NOT do

- **Pattern matching is not proof.** The 11 patterns catch well-known secret *shapes*; an unusual format or an obfuscated secret will be missed, and a shape can occasionally false-positive (e.g. a placeholder that looks like a key). Treat findings as "investigate", not "definitely compromised".
- **Does not scan image config / env.** Only layer file contents are scanned.
- **Does not validate or revoke.** It tells you where the secret is — rotating it is on you, and you should assume a secret found in a pushed image is already compromised.
- **No registry integration.** It reads tarballs / directories, it does not pull from registries.
- **Skips large and binary files.** A secret hidden in a 50 MB blob or a binary will not be found (the skip counts are reported so you can see this).

## Requirements & tests

- Python 3.8+ — **standard library only** (`tarfile`, `re`, `argparse`). No installs.
- Run the suite: `python -m unittest discover -s tests -v` (8 tests, all green — they build fixture image tarballs in-test, no Docker needed).

## License

MIT — see [LICENSE](LICENSE).

## Built by Ingenious AI

Part of the [Ingenious AI](https://github.com/Iceman2050) security platform suite. Get early access:

- [DisclosureGuard](https://wa.me/5016691053?text=Hi%20Ingenious%20AI%21%20I%20want%20early%20access%20to%20DisclosureGuard.)
- [ModelMinder](https://wa.me/5016691053?text=Hi%20Ingenious%20AI%21%20I%20want%20early%20access%20to%20ModelMinder.)
- [TermsWatch](https://wa.me/5016691053?text=Hi%20Ingenious%20AI%21%20I%20want%20early%20access%20to%20TermsWatch.)
- [Vibe-Code Audit](https://wa.me/5016691053?text=Hi%20Ingenious%20AI%21%20I%20want%20early%20access%20to%20Vibe-Code%20Audit.)
- [Rogue-Agent Defense](https://wa.me/5016691053?text=Hi%20Ingenious%20AI%21%20I%20want%20early%20access%20to%20Rogue-Agent%20Defense.)
- [BreachHunter](https://wa.me/5016691053?text=Hi%20Ingenious%20AI%21%20I%20want%20early%20access%20to%20BreachHunter.)
- [ChatBreaker](https://wa.me/5016691053?text=Hi%20Ingenious%20AI%21%20I%20want%20early%20access%20to%20ChatBreaker.)
- [Agent Flight Recorder](https://wa.me/5016691053?text=Hi%20Ingenious%20AI%21%20I%20want%20early%20access%20to%20Agent%20Flight%20Recorder.)
- [Agent Auth Gateway](https://wa.me/5016691053?text=Hi%20Ingenious%20AI%21%20I%20want%20early%20access%20to%20Agent%20Auth%20Gateway.)
- [DomainGuard](https://wa.me/5016691053?text=Hi%20Ingenious%20AI%21%20I%20want%20early%20access%20to%20DomainGuard.)
- [ContentCraft AI](https://wa.me/5016691053?text=Hi%20Ingenious%20AI%21%20I%20want%20early%20access%20to%20ContentCraft%20AI.)

Built with Muse — try it free: invite code `2HCQH1`
