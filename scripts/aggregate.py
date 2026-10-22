#!/usr/bin/env python3
"""
aggregate.py — combine per-host php2shell_detect.py --json outputs into one roster.

USAGE
  python3 aggregate.py results/            # dir of *.json (one per host)
  python3 aggregate.py a.json b.json ...   # explicit files
  python3 aggregate.py results/ --csv      # CSV instead of a table

Reads only. Prints hosts sorted by severity (vulnerable, then EOL, then investigate,
then clean). Exits 1 if any host needs action, else 0 — useful as a CI gate.
"""

import glob
import json
import os
import sys

RANK = {"VULNERABLE": 0, "EOL": 1, "UNKNOWN": 2, "PATCHED": 3}
EXIT_RANK = {2: 0, 1: 1, 0: 3}  # host overall_exit -> sort bucket


def load(paths):
    files = []
    for p in paths:
        if os.path.isdir(p):
            files.extend(sorted(glob.glob(os.path.join(p, "*.json"))))
        else:
            files.append(p)
    hosts = []
    for f in files:
        try:
            with open(f, "rt") as fh:
                hosts.append(json.load(fh))
        except Exception as e:  # noqa: BLE001
            sys.stderr.write(f"skip {f}: {e}\n")
    return hosts


def worst_status(host):
    statuses = [r.get("status", "UNKNOWN") for r in host.get("runtimes", [])]
    if not statuses:
        # no runtimes but maybe mod_php flagged
        return "INVESTIGATE" if host.get("mod_php") else "CLEAN"
    return min(statuses, key=lambda s: RANK.get(s, 2))


def rows(hosts):
    out = []
    for h in hosts:
        worst = worst_status(h)
        vers = ", ".join(
            sorted({r.get("version", "?") for r in h.get("runtimes", [])})
        ) or "-"
        out.append(
            {
                "host": h.get("host", "?"),
                "worst": worst,
                "versions": vers,
                "mod_php": "yes" if h.get("mod_php") else "",
                "exit": h.get("overall_exit", 2),
            }
        )
    out.sort(key=lambda r: (EXIT_RANK.get(r["exit"], 0), r["host"]))
    return out


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    as_csv = "--csv" in sys.argv[1:]
    if not args:
        sys.stderr.write(__doc__)
        sys.exit(2)

    hosts = load(args)
    r = rows(hosts)

    if as_csv:
        print("host,worst_status,versions,mod_php,exit")
        for x in r:
            print(f'{x["host"]},{x["worst"]},"{x["versions"]}",{x["mod_php"]},{x["exit"]}')
    else:
        w = max([len(x["host"]) for x in r] + [4])
        print(f'{"HOST":<{w}}  {"STATUS":<11}  {"MOD_PHP":<7}  VERSIONS')
        print("-" * (w + 40))
        for x in r:
            print(f'{x["host"]:<{w}}  {x["worst"]:<11}  {x["mod_php"]:<7}  {x["versions"]}')
        need = sum(1 for x in r if x["exit"] in (1, 2))
        print()
        print(f"{len(r)} host(s) scanned, {need} need attention.")

    sys.exit(1 if any(x["exit"] in (1, 2) for x in r) else 0)


if __name__ == "__main__":
    main()
