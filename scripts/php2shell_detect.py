#!/usr/bin/env python3
"""
php2shell_detect.py
Read-only detection for PHP2Shell: CVE-2026-109618 and CVE-2026-109619.

WHAT THIS DOES
  - Finds PHP runtimes on the local host (CLI, PHP-FPM, mod_php under Apache).
  - Reports each runtime's version.
  - Compares it to the fixed releases and labels it PATCHED / VULNERABLE / EOL / UNKNOWN.
  - Checks the distro package changelog for a backported fix (avoids false positives
    where the upstream version looks old but the vendor patched it).
  - Checks whether workers were restarted after the patch was installed.
  - Reports the interim-mitigation settings and whether the session.upload_progress
    attack path is ENABLED (i.e. reachable) -- without triggering it.

WHAT THIS DOES NOT DO
  - It does not exploit anything, send network payloads, or write/modify any file.
    Every operation is a local read. Safe to run on production.

USAGE
  python3 php2shell_detect.py            # human-readable report
  python3 php2shell_detect.py --json     # machine-readable JSON (one object)

EXIT CODES
  0  no vulnerable runtime found
  1  a vulnerable or EOL runtime was found (action required)
  2  at least one runtime could not be classified (investigate)

Run it across a fleet with your own orchestration (Ansible 'script' module, an SSH
loop, etc.) and collect the --json output into one roster. Run as root where you can,
so config and changelog reads are complete.
"""

import json
import os
import re
import shutil
import socket
import subprocess
import sys
from datetime import datetime

# --- Fixed versions per branch -------------------------------------------------
# A runtime on branch X is vulnerable if its patch number is BELOW the value here.
FIXED = {"8.2": 35, "8.3": 36, "8.4": 27, "8.5": 12}
# Branches with no upstream fix at all (end of life):
EOL_BRANCHES = {
    "5.0", "5.1", "5.2", "5.3", "5.4", "5.5", "5.6",
    "7.0", "7.1", "7.2", "7.3", "7.4", "8.0", "8.1",
}
CVE_RE = re.compile(r"CVE-2026-10961[89]", re.IGNORECASE)
VER_RE = re.compile(r"(\d+)\.(\d+)\.(\d+)")


def run(cmd, timeout=15):
    """Run a command, return (rc, stdout, stderr). Never raises."""
    try:
        p = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        return p.returncode, p.stdout, p.stderr
    except Exception as e:  # noqa: BLE001 - detection must never crash the host loop
        return 127, "", str(e)


def classify_version(verstr):
    """Return (state, detail). state in PATCHED/VULNERABLE/EOL/UNKNOWN."""
    core = verstr.split("-", 1)[0]  # 8.3.30-1ubuntu1 -> 8.3.30
    m = VER_RE.match(core)
    if not m:
        return "UNKNOWN", f"could not parse version '{verstr}'"
    major, minor, patch = (int(x) for x in m.groups())
    branch = f"{major}.{minor}"

    if branch in EOL_BRANCHES:
        return "EOL", (
            f"branch {branch} is end-of-life; no upstream fix. "
            f"Needs a vendor backport or an upgrade."
        )
    if branch in FIXED:
        need = FIXED[branch]
        if patch >= need:
            return "PATCHED", f"{branch}.{patch} >= fixed {branch}.{need} (upstream)."
        return "VULNERABLE", (
            f"{branch}.{patch} < fixed {branch}.{need}. "
            f"Upgrade, or confirm a distro backport."
        )
    return "UNKNOWN", f"branch {branch} not in the fixed-version table; verify manually."


def changelog_backport():
    """Best-effort: does a package changelog cite these CVEs? Returns a string."""
    if shutil.which("rpm"):
        rc, out, _ = run(["rpm", "-q", "--changelog", "php-common", "php"])
        if rc == 0 and CVE_RE.search(out):
            return "yes (rpm changelog cites the CVE)"
    import glob
    import gzip

    for pat in (
        "/usr/share/doc/php*-common/changelog.Debian.gz",
        "/usr/share/doc/php*/changelog.Debian.gz",
    ):
        for path in glob.glob(pat):
            try:
                with gzip.open(path, "rt", errors="ignore") as fh:
                    if CVE_RE.search(fh.read()):
                        return "yes (deb changelog cites the CVE)"
            except Exception:  # noqa: BLE001
                continue
    return "not found (does not prove absence; check your vendor advisory)"


def php_ini_dump(php_cmd):
    """Return `php -i` text for the given php invocation, or ''."""
    rc, out, _ = run([php_cmd, "-i"])
    return out if rc == 0 else ""


def ini_value(dump, key):
    for line in dump.splitlines():
        if line.startswith(key):
            return line.strip()
    return ""


def worker_restart_info(procnames):
    """Report the oldest start time among matching processes (proc read-only)."""
    out = {}
    for name in procnames:
        rc, pout, _ = run(["pgrep", "-f", name])
        pids = [p for p in pout.split() if p.isdigit()]
        if not pids:
            continue
        starts = []
        for pid in pids:
            try:
                starts.append(os.stat(f"/proc/{pid}").st_mtime)
            except OSError:
                pass
        if starts:
            oldest = min(starts)
            out[name] = datetime.fromtimestamp(oldest).strftime("%Y-%m-%d %H:%M:%S")
    return out


def detect():
    report = {
        "host": socket.gethostname(),
        "date": datetime.now().isoformat(timespec="seconds"),
        "cves": ["CVE-2026-109618", "CVE-2026-109619"],
        "fixed_versions": {b: f"{b}.{p}" for b, p in FIXED.items()},
        "runtimes": [],
        "notes": [],
        "overall_exit": 0,
    }

    def bump(code):
        if code > report["overall_exit"]:
            report["overall_exit"] = code

    php_cmd = shutil.which("php")

    # 1) CLI
    if php_cmd:
        rc, out, _ = run([php_cmd, "-r", "echo PHP_VERSION;"])
        if rc == 0 and out.strip():
            report["runtimes"].append(examine("php-cli", out.strip(), php_cmd, bump))

    # 2) PHP-FPM, trying common binary names
    fpm_names = [
        "php-fpm", "php-fpm8.5", "php-fpm8.4", "php-fpm8.3", "php-fpm8.2",
        "php8.5-fpm", "php8.4-fpm", "php8.3-fpm", "php8.2-fpm",
    ]
    seen = set()
    for fpm in fpm_names:
        path = shutil.which(fpm)
        if not path or path in seen:
            continue
        seen.add(path)
        rc, out, _ = run([fpm, "-v"])
        m = VER_RE.search(out)
        if m:
            report["runtimes"].append(
                examine(fpm, m.group(0), php_cmd, bump)
            )

    # worker restart timing
    restarts = worker_restart_info(["php-fpm", "httpd", "apache2"])
    if restarts:
        report["worker_oldest_start"] = restarts
        report["notes"].append(
            "Compare each worker start time with when the PHP package was patched. "
            "A worker older than the patch is still running vulnerable code -- restart it."
        )

    # 3) mod_php under Apache
    ctl = shutil.which("apachectl") or shutil.which("apache2ctl")
    if ctl:
        rc, out, _ = run([ctl, "-M"])
        if rc == 0 and re.search(r"php[0-9_]*module", out, re.IGNORECASE):
            report["mod_php"] = True
            report["notes"].append(
                "mod_php is loaded in Apache -- the HIGHEST-RISK configuration for "
                "CVE-2026-109618 (demonstrated exploit against mod_php with default config). "
                "Prioritize this host."
            )
            bump(2)

    # 4) container hint
    in_container = os.path.exists("/.dockerenv")
    if not in_container:
        try:
            with open("/proc/1/cgroup", "rt", errors="ignore") as fh:
                if re.search(r"docker|kubepods|containerd", fh.read()):
                    in_container = True
        except OSError:
            pass
    if in_container:
        report["container"] = True
        report["notes"].append(
            "This looks like a container. Scan the IMAGE in your registry (Trivy/Grype) "
            "and rebuild from a patched base image; restarting alone won't fix a baked-in PHP."
        )

    return report


def examine(label, verstr, php_cmd, bump):
    state, detail = classify_version(verstr)
    entry = {"runtime": label, "version": verstr, "status": state, "detail": detail}

    if state in ("VULNERABLE", "EOL"):
        entry["distro_backport"] = changelog_backport()
        bump(1)
    elif state == "UNKNOWN":
        bump(2)

    # config / mitigation reachability (shared FPM/CLI ini via php binary)
    if php_cmd:
        dump = php_ini_dump(php_cmd)
        if dump:
            cfg = {}
            for key in (
                "session.upload_progress.enabled",
                "memory_limit",
                "post_max_size",
                "fatal_error_backtraces",
            ):
                val = ini_value(dump, key)
                if val:
                    cfg[key] = val
            entry["config"] = cfg
            upl = cfg.get("session.upload_progress.enabled", "")
            if re.search(r"=>\s*(On|1)\b", upl):
                entry["upload_progress_reachable"] = True
    return entry


def print_human(r):
    line = "-" * 60
    print(f"PHP2Shell detection (CVE-2026-109618 / CVE-2026-109619)")
    print(f"Host: {r['host']}   Date: {r['date']}")
    print("Read-only. No exploitation performed.")
    print(f"Fixed releases: " + ", ".join(sorted(r["fixed_versions"].values())))

    if not r["runtimes"]:
        print(line)
        print("No PHP runtime detected on this host.")
    for e in r["runtimes"]:
        print(line)
        print(f"RUNTIME: {e['runtime']}")
        print(f"  version: {e['version']}")
        print(f"  status : {e['status']}")
        print(f"  detail : {e['detail']}")
        if "distro_backport" in e:
            print(f"  distro backport: {e['distro_backport']}")
        if "config" in e and e["config"]:
            print("  config (this runtime):")
            for k, v in e["config"].items():
                print(f"    {v}")
            if e.get("upload_progress_reachable"):
                print("    NOTE: session.upload_progress is ON -> one known "
                      "CVE-2026-109619 path is reachable.")

    if r.get("worker_oldest_start"):
        print(line)
        print("Worker start times (restart anything older than your patch time):")
        for name, when in r["worker_oldest_start"].items():
            print(f"  {name}: oldest worker started {when}")

    for n in r["notes"]:
        print(line)
        print(f"NOTE: {n}")

    print(line)
    verdicts = {
        0: "RESULT: no vulnerable runtime detected on this host.",
        1: "RESULT: ACTION REQUIRED -- a vulnerable or EOL runtime was found.",
        2: "RESULT: INVESTIGATE -- a runtime could not be fully classified.",
    }
    print(verdicts[r["overall_exit"]])
    print()
    print("After patching, RESTART every PHP worker and rebuild container images.")
    print("A patched binary with old workers still running is still exposed.")


def main():
    want_json = "--json" in sys.argv[1:]
    r = detect()
    if want_json:
        print(json.dumps(r))
    else:
        print_human(r)
    sys.exit(r["overall_exit"])


if __name__ == "__main__":
    main()
