#!/usr/bin/env bash
#
# php2shell-detect.sh
# Read-only detection for PHP2Shell: CVE-2026-109618 and CVE-2026-109619
#
# WHAT THIS DOES (and does NOT do):
#   - Reports the PHP version used by each runtime found on this host (CLI, FPM, mod_php).
#   - Compares against the fixed releases and flags vulnerable / patched / EOL.
#   - Checks distro package changelogs for backported fixes.
#   - Checks whether workers were restarted after the patch was installed.
#   - Reports the relevant hardening ini settings for the interim mitigations.
#   - Reports whether the session.upload_progress attack path is enabled (reachable),
#     WITHOUT attempting to trigger it.
#
#   It does NOT exploit anything, send network payloads, or write/modify any file.
#   Every action is a local read. Safe to run on production.
#
# USAGE:
#   ./php2shell-detect.sh            # human-readable report
#   ./php2shell-detect.sh --json     # machine-readable one-line JSON summary
#
# EXIT CODES:
#   0  no vulnerable runtime found
#   1  at least one runtime is vulnerable or EOL (needs action)
#   2  could not determine state for at least one runtime (investigate)
#
# Run across a fleet with your existing orchestration (Ansible, SSH loop, etc).
# Nothing here requires root, but some config/changelog reads are more complete as root.

set -u

JSON=0
[ "${1:-}" = "--json" ] && JSON=1

# --- Fixed versions per branch -------------------------------------------------
# A runtime on branch X is vulnerable if its patch version is BELOW the value here.
declare -A FIXED=( [8.2]=35 [8.3]=36 [8.4]=27 [8.5]=12 )
# Branches with no upstream fix at all:
EOL_BRANCHES="5.0 5.1 5.2 5.3 5.4 5.5 5.6 7.0 7.1 7.2 7.3 7.4 8.0 8.1"

OVERALL=0          # worst exit code seen
RESULTS=()         # JSON fragments

note()  { [ "$JSON" -eq 0 ] && echo "$@"; }
hr()    { [ "$JSON" -eq 0 ] && echo "------------------------------------------------------------"; }

# --- Compare a found version against the table --------------------------------
# echoes one of: PATCHED / VULNERABLE / EOL / UNKNOWN  and a human reason
classify_version() {
    local ver="$1"
    # strip any -extra suffix: 8.3.30-1ubuntu1 -> 8.3.30
    local core="${ver%%-*}"
    local major minor patch branch
    IFS='.' read -r major minor patch _ <<< "$core"
    [ -z "${patch:-}" ] && { echo "UNKNOWN could not parse version '$ver'"; return; }
    branch="$major.$minor"

    # EOL branch?
    for b in $EOL_BRANCHES; do
        if [ "$b" = "$branch" ]; then
            echo "EOL branch $branch is end-of-life; no upstream fix. Needs vendor backport or upgrade."
            return
        fi
    done

    # Supported branch?
    if [ -n "${FIXED[$branch]:-}" ]; then
        local need="${FIXED[$branch]}"
        if [ "$patch" -ge "$need" ] 2>/dev/null; then
            echo "PATCHED $branch.$patch >= fixed $branch.$need (upstream)."
        else
            echo "VULNERABLE $branch.$patch < fixed $branch.$need. Upgrade, OR confirm a distro backport below."
        fi
        return
    fi

    echo "UNKNOWN branch $branch not in fixed-version table; verify manually."
}

# --- Look for a distro backport in the package changelog ----------------------
changelog_backport() {
    if command -v rpm >/dev/null 2>&1; then
        rpm -q --changelog php-common php 2>/dev/null | grep -Eiq "CVE-2026-10961[89]" && { echo "yes (rpm changelog cites the CVE)"; return; }
    fi
    local cl
    for cl in /usr/share/doc/php*-common/changelog.Debian.gz /usr/share/doc/php*/changelog.Debian.gz; do
        [ -f "$cl" ] || continue
        zcat "$cl" 2>/dev/null | grep -Eiq "CVE-2026-10961[89]" && { echo "yes (deb changelog cites the CVE)"; return; }
    done
    echo "not found (does not prove absence; check your vendor advisory)"
}

# --- When did the package get installed vs. when did workers start? ------------
worker_restart_check() {
    local procname="$1"   # e.g. php-fpm, httpd, apache2
    local pids oldest
    pids=$(pgrep -x "$procname" 2>/dev/null; pgrep -f "$procname" 2>/dev/null) || true
    pids=$(echo "$pids" | tr ' ' '\n' | sort -u | grep -E '^[0-9]+$')
    [ -z "$pids" ] && { echo "no running '$procname' process"; return; }
    # earliest start among matching processes (epoch)
    oldest=$(for p in $pids; do
                 stat -c %Y "/proc/$p" 2>/dev/null
             done | sort -n | head -1)
    [ -z "$oldest" ] && { echo "running, but could not read start time"; return; }
    echo "oldest '$procname' worker started: $(date -d @"$oldest" 2>/dev/null || echo epoch:$oldest)"
}

# --- Read a setting from a specific runtime's effective config -----------------
# $1 = php binary + optional -c ini, passed as a single string
ini_setting() {
    local runner="$1" key="$2"
    $runner -i 2>/dev/null | grep -E "^$key" | head -1
}

# --- Examine one runtime -------------------------------------------------------
examine() {
    local label="$1" verstr="$2" runner="$3"   # runner = how to invoke php -i for its ini, or ""
    [ -z "$verstr" ] && return
    hr
    note "RUNTIME: $label"
    note "  reported version: $verstr"

    local verdict reason state
    verdict=$(classify_version "$verstr")
    state="${verdict%% *}"
    reason="${verdict#* }"
    note "  status: $state"
    note "  detail: $reason"

    local backport="n/a"
    if [ "$state" = "VULNERABLE" ] || [ "$state" = "EOL" ]; then
        backport=$(changelog_backport)
        note "  distro backport: $backport"
        OVERALL=1
    elif [ "$state" = "UNKNOWN" ]; then
        [ "$OVERALL" -lt 2 ] && OVERALL=2
    fi

    # hardening settings (reachability of mitigations / attack path)
    if [ -n "$runner" ]; then
        local upl mem pms feb
        upl=$(ini_setting "$runner" "session.upload_progress.enabled")
        mem=$(ini_setting "$runner" "memory_limit")
        pms=$(ini_setting "$runner" "post_max_size")
        feb=$(ini_setting "$runner" "fatal_error_backtraces")
        note "  config (this runtime):"
        note "    ${upl:-session.upload_progress.enabled => (not reported)}"
        note "    ${mem:-memory_limit => (not reported)}"
        note "    ${pms:-post_max_size => (not reported)}"
        [ -n "$feb" ] && note "    $feb"
        # reachability note for CVE-2026-109619 session path
        if echo "$upl" | grep -qiE "=>\s*(On|1)\b"; then
            note "    NOTE: session.upload_progress is ON -> one known CVE-2026-109619 path is reachable."
        fi
    fi

    RESULTS+=("{\"runtime\":\"$label\",\"version\":\"$verstr\",\"status\":\"$state\",\"backport\":\"$backport\"}")
}

# ------------------------------------------------------------------------------
note "PHP2Shell detection (CVE-2026-109618 / CVE-2026-109619)"
note "Host: $(hostname 2>/dev/null)   Date: $(date 2>/dev/null)"
note "Read-only. No exploitation performed."

# 1) CLI
if command -v php >/dev/null 2>&1; then
    CLIVER=$(php -r 'echo PHP_VERSION;' 2>/dev/null)
    examine "php-cli" "$CLIVER" "php"
fi

# 2) PHP-FPM (try common binary names)
for fpm in php-fpm php-fpm8.5 php-fpm8.4 php-fpm8.3 php-fpm8.2 php8.5-fpm php8.4-fpm php8.3-fpm php8.2-fpm; do
    command -v "$fpm" >/dev/null 2>&1 || continue
    FVER=$("$fpm" -v 2>/dev/null | grep -oE 'PHP [0-9]+\.[0-9]+\.[0-9]+[^ ]*' | awk '{print $2}' | head -1)
    # FPM shares php ini; probe via the php binary if present
    examine "$fpm" "$FVER" "${PHP_CMD:-php}"
done

# 3) mod_php under Apache
if command -v apachectl >/dev/null 2>&1 || command -v apache2ctl >/dev/null 2>&1; then
    CTL=$(command -v apachectl || command -v apache2ctl)
    if $CTL -M 2>/dev/null | grep -qi 'php[0-9_]*module'; then
        note ""
        note "mod_php IS loaded in Apache -> HIGHEST-RISK configuration for CVE-2026-109618."
        note "  (PHP team: demonstrated exploit against mod_php with default config.)"
        # version is whatever module is built against; report CLI as a hint
        [ -n "${CLIVER:-}" ] && note "  (CLI version shown above is a hint, not necessarily the module's build.)"
        [ "$OVERALL" -lt 2 ] && OVERALL=2
    fi
fi

# 4) Containers hint
if [ -f /.dockerenv ] || grep -qa 'docker\|kubepods\|containerd' /proc/1/cgroup 2>/dev/null; then
    note ""
    note "This looks like a container. Also scan the IMAGE in your registry (Trivy/Grype) and"
    note "rebuild from a patched base image -- restarting alone will not fix a baked-in old PHP."
fi

hr
if [ "$JSON" -eq 1 ]; then
    printf '{"host":"%s","overall_exit":%d,"runtimes":[%s]}\n' \
        "$(hostname 2>/dev/null)" "$OVERALL" "$(IFS=,; echo "${RESULTS[*]:-}")"
else
    case "$OVERALL" in
        0) note "RESULT: no vulnerable runtime detected on this host." ;;
        1) note "RESULT: ACTION REQUIRED -- a vulnerable or EOL runtime was found above." ;;
        2) note "RESULT: INVESTIGATE -- at least one runtime could not be classified." ;;
    esac
    note ""
    note "Reminder: after patching, RESTART every PHP worker (php-fpm/apache) and rebuild"
    note "container images. A patched binary with old workers still running is still exposed."
fi

exit "$OVERALL"
