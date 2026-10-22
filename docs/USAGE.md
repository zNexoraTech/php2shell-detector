# Usage

All commands are read-only and safe to run on production. Run as root where you can,
so that configuration and package-changelog reads are complete.

## Single host

```bash
# Python
python3 scripts/php2shell_detect.py
python3 scripts/php2shell_detect.py --json

# Bash
bash scripts/php2shell-detect.sh
bash scripts/php2shell-detect.sh --json
```

## Across a fleet

### Ansible

```bash
# Run on every host, print per-host JSON to your controller
ansible all -m script -a "scripts/php2shell_detect.py --json"
```

Or as a play that saves one JSON file per host:

```yaml
- hosts: all
  gather_facts: false
  tasks:
    - name: Run PHP2Shell detector
      ansible.builtin.script: scripts/php2shell_detect.py --json
      register: scan
      changed_when: false
    - name: Save result
      delegate_to: localhost
      ansible.builtin.copy:
        content: "{{ scan.stdout }}"
        dest: "results/{{ inventory_hostname }}.json"
```

### SSH loop

No need to copy the file first — stream it to each host over stdin:

```bash
mkdir -p results
while read -r h; do
  ssh "$h" python3 - --json < scripts/php2shell_detect.py > "results/$h.json"
done < hosts.txt
```

### Container images

The detector inspects a running host. For images in your registry, scan the image
itself and rebuild from a patched base:

```bash
# Example with Trivy
trivy image --scanners vuln your-registry/your-php-app:tag | grep -E "CVE-2026-10961[89]"
```

Restarting a container does not fix a PHP baked into an old image — rebuild and
redeploy.

## Collecting results into one roster

After writing one JSON file per host into `results/`, summarize them:

```bash
python3 scripts/aggregate.py results/
```

This prints a single table sorted by severity (vulnerable first, then EOL, then
investigate, then clean) and exits non-zero if any host needs action — handy in CI.

## Interpreting the output

| Field | Meaning |
| --- | --- |
| `status: VULNERABLE` | Runtime version is below the fixed release. Patch, or confirm a distro backport. |
| `status: EOL` | Branch 8.1 or older — no upstream fix. Backport or upgrade. |
| `status: PATCHED` | At or above the fixed release upstream. |
| `status: UNKNOWN` | Could not parse/classify — verify manually. |
| `distro_backport: yes ...` | The package changelog cites the CVE; a `VULNERABLE`-looking upstream version may actually be fixed. |
| `upload_progress_reachable: true` | `session.upload_progress` is enabled — one known CVE-2026-109619 path is reachable. Reported only, never triggered. |
| `mod_php: true` | Highest-risk configuration. Prioritize. |

## After patching

1. Upgrade to the fixed release (or apply the vendor backport).
2. **Restart every PHP worker** (php-fpm, apache) — long-lived workers keep the old code.
3. **Rebuild container images** and redeploy.
4. Re-run the detector and confirm every runtime reads `PATCHED`.
5. Review logs for signs of pre-patch compromise (worker segfaults, "Allowed memory
   size exhausted" spikes, unusual upload POSTs, PHP files modified since 20 Oct 2026).
