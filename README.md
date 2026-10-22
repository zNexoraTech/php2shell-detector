# php2shell-detector

Read-only detection for **PHP2Shell** — the two critical PHP core vulnerabilities
**CVE-2026-109618** and **CVE-2026-109619** (both CVSS v4.0 **9.2**, unauthenticated
remote code execution), disclosed and patched on 21 October 2026.

This is a **defensive detection tool**. It tells you *which of your hosts need
patching* by reading installed versions and configuration. It does **not** exploit
anything, send network payloads, or modify any file — every operation is a local
read, so it is safe to run on production.

> If you need to *prove* exploitability rather than detect exposure, do that in an
> isolated lab replica using your scanner vendor's vetted check or an external
> penetration-testing firm under written authorization. This repository
> deliberately contains no exploit or proof-of-concept code.

## The vulnerabilities

| CVE | Nickname | Class | What goes wrong |
| --- | --- | --- | --- |
| CVE-2026-109618 | PHP2Shell | Out-of-memory corruption | When a request exhausts the memory limit mid-parse, PHP aborts with internal request data only partly initialized; cleanup then treats that invalid state as valid. |
| CVE-2026-109619 | PHP2Shell | Stale global state | A worker keeps global state that still points into freed request memory; a later request on the same worker uses it (use-after-free). |

Both are unauthenticated and remote. PHP considers **Apache with mod_php** the
highest-risk configuration. PHP-FPM, php-cgi, FrankenPHP and LiteSpeed are also
affected.

## Fixed versions

Upgrade to the first fixed release on your branch:

| Branch | Fixed in |
| --- | --- |
| 8.5 | **8.5.12** |
| 8.4 | **8.4.27** |
| 8.3 | **8.3.36** |
| 8.2 | **8.2.35** |
| 8.1 and older | End of life — no upstream fix. Use a distro/LTS backport or upgrade. |

Updating is the only complete mitigation. **Restart every PHP worker** after
patching and **rebuild container images** — a patched binary with old workers still
running is still exposed.

## What the detector reports

For each host:

- Every PHP runtime found: CLI, PHP-FPM (any common binary name), mod_php under Apache.
- A verdict per runtime: `PATCHED` / `VULNERABLE` / `EOL` / `UNKNOWN`.
- Distro **backport** status from the package changelog (avoids false positives where
  the upstream version looks old but the vendor patched it).
- **Worker restart** timing, to catch "patched binary, stale worker still vulnerable".
- The interim-mitigation settings, and whether `session.upload_progress` is enabled
  (one known CVE-2026-109619 attack path is *reachable* — reported, never triggered).
- A highest-risk flag for mod_php, and a reminder to rebuild the image in containers.

## Quick start

Python (standard library only, Python 3.6+):

```bash
python3 scripts/php2shell_detect.py          # human-readable report
python3 scripts/php2shell_detect.py --json   # machine-readable JSON
```

Bash equivalent (no Python needed):

```bash
bash scripts/php2shell-detect.sh
bash scripts/php2shell-detect.sh --json
```

Run as root where you can, so config and changelog reads are complete.

### Exit codes

| Code | Meaning |
| --- | --- |
| 0 | No vulnerable runtime found |
| 1 | A vulnerable or EOL runtime was found (action required) |
| 2 | A runtime could not be classified (investigate) |

Use these to gate automation.

## Running across a fleet

See [`docs/USAGE.md`](docs/USAGE.md) for Ansible, SSH-loop, and container-image
examples, plus how to collect the per-host JSON into one roster.

```bash
# Ansible
ansible all -m script -a "scripts/php2shell_detect.py --json"

# SSH loop (no copy needed — stream the script to the host)
for h in $(cat hosts.txt); do
  ssh "$h" python3 - --json < scripts/php2shell_detect.py
done
```

## Keeping it current

The `FIXED` table at the top of each script is the source of truth. If PHP issues a
follow-up release, or your distribution publishes its backported versions, update
that table. The changelog check already handles the backport case.

## Contributing

Issues and pull requests welcome — for detection accuracy, additional runtime/distro
coverage, and output formats. Please **do not** submit exploit code, proof-of-concept
payloads, or anything that attempts to trigger the vulnerabilities; such
contributions will be declined to keep this repository safe to share. See
[`CONTRIBUTING.md`](CONTRIBUTING.md).

## References

- PHP advisory GHSA-w8hw-w9fx-j79w (CVE-2026-109618)
- PHP advisory GHSA-6wmf-4rv5-p3rp (CVE-2026-109619)
- PHP supported versions: https://www.php.net/supported-versions.php
- UK NCSC guidance on the PHP vulnerabilities

## License

MIT — see [`LICENSE`](LICENSE).

## Disclaimer

Provided as-is, without warranty. Detection reflects version and configuration state;
always confirm against your vendor's advisory and a patched inventory. Run only on
systems you are authorized to assess.
