# Contributing

Thanks for helping improve PHP2Shell detection.

## Welcome

- Detection accuracy fixes (version parsing, branch tables).
- Additional runtime and distribution coverage.
- New output formats and fleet-collection helpers.
- Documentation improvements.

## Not accepted

To keep this repository safe to clone and share, we will decline:

- Exploit code or proof-of-concept payloads for CVE-2026-109618 / CVE-2026-109619.
- Code that attempts to trigger the vulnerabilities on a remote host.
- Links that distribute the above.

This project detects exposure by reading version and configuration state. It is
not an exploitation tool.

## Keeping the fixed-version table current

The `FIXED` table at the top of each detector is the source of truth. When PHP ships
a follow-up release, or a distro publishes backported versions, update that table and
note the source in your PR.

## Before you open a PR

- `python3 -m py_compile scripts/*.py`
- Run the detector on at least one host and paste the output (redact hostnames).
