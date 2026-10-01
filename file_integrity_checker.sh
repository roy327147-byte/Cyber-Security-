#!/usr/bin/env bash
#
# Task 1 - File Integrity Checker
#
# Calculates file hashes (SHA-256 / MD5), stores them in a baseline,
# and later re-checks the files to detect modifications.
#
# Usage:
#   ./file_integrity_checker.sh init   file1 [file2 ...]   # create/update baseline
#   ./file_integrity_checker.sh check  [file1 ...]         # verify against baseline
#   ./file_integrity_checker.sh hash   file1 [file2 ...]   # just print hashes
#   ./file_integrity_checker.sh compare fileA fileB        # compare two files
#   ./file_integrity_checker.sh list                       # show baseline
#
# Options:
#   -a sha256|md5     hash algorithm (default: sha256)
#   -b <baseline>     baseline file (default: ./baseline.txt)
#

set -uo pipefail

ALGO="sha256"
BASELINE="./baseline.txt"

RED=$'\033[0;31m'; GREEN=$'\033[0;32m'; YELLOW=$'\033[0;33m'
BLUE=$'\033[0;34m'; BOLD=$'\033[1m'; RESET=$'\033[0m'

usage() {
    sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'
    exit 1
}

# ---------------------------------------------------------------- helpers ---

hash_file() {
    local file="$1"

    if [[ ! -f "$file" ]]; then
        echo "MISSING"
        return 1
    fi
    if [[ ! -r "$file" ]]; then
        echo "UNREADABLE"
        return 1
    fi

    case "$ALGO" in
        sha256) sha256sum "$file" | awk '{print $1}' ;;
        md5)    md5sum    "$file" | awk '{print $1}' ;;
        *)      echo "Unsupported algorithm: $ALGO" >&2; exit 1 ;;
    esac
}

# Absolute path so the baseline is not tied to the current directory
abs_path() {
    local f="$1"
    local dir base
    dir=$(cd "$(dirname "$f")" 2>/dev/null && pwd) || { echo "$f"; return; }
    base=$(basename "$f")
    echo "${dir%/}/$base"
}

baseline_lookup() {
    local path="$1"
    awk -F'|' -v p="$path" '$1 == p {print $3}' "$BASELINE" 2>/dev/null | tail -n 1
}

# ------------------------------------------------------------------ init ----

cmd_init() {
    [[ $# -gt 0 ]] || { echo "No files given." >&2; exit 1; }

    local tmp; tmp=$(mktemp)
    [[ -f "$BASELINE" ]] && cp "$BASELINE" "$tmp"

    local stamp; stamp=$(date '+%Y-%m-%d %H:%M:%S')
    local added=0 skipped=0

    printf '%s%-10s %-64s %s%s\n' "$BOLD" "STATUS" "HASH" "FILE" "$RESET"

    for f in "$@"; do
        local path hash
        path=$(abs_path "$f")
        hash=$(hash_file "$f") || { printf '%sSKIP%s       %-64s %s\n' \
                                    "$YELLOW" "$RESET" "$hash" "$f"
                                    ((skipped++)); continue; }
        # drop any previous entry for this path, then append the new one
        grep -v -F "$path|" "$tmp" > "$tmp.new" 2>/dev/null || true
        mv "$tmp.new" "$tmp"
        printf '%s|%s|%s|%s\n' "$path" "$ALGO" "$hash" "$stamp" >> "$tmp"
        printf '%sSAVED%s      %-64s %s\n' "$GREEN" "$RESET" "$hash" "$f"
        ((added++))
    done

    mv "$tmp" "$BASELINE"
    echo
    echo "Baseline: $BASELINE   (recorded: $added, skipped: $skipped)"
}

# ----------------------------------------------------------------- check ----

cmd_check() {
    if [[ ! -f "$BASELINE" ]]; then
        echo "No baseline found at '$BASELINE'. Run 'init' first." >&2
        exit 1
    fi

    local targets=()
    if [[ $# -gt 0 ]]; then
        for f in "$@"; do targets+=("$(abs_path "$f")"); done
    else
        mapfile -t targets < <(cut -d'|' -f1 "$BASELINE")
    fi

    local ok=0 modified=0 missing=0 unknown=0

    printf '%s%-12s %s%s\n' "$BOLD" "STATUS" "FILE" "$RESET"
    printf '%s\n' "------------------------------------------------------------"

    for path in "${targets[@]}"; do
        local expected actual
        expected=$(baseline_lookup "$path")

        if [[ -z "$expected" ]]; then
            printf '%s%-12s%s %s\n' "$BLUE" "UNKNOWN" "$RESET" "$path"
            ((unknown++)); continue
        fi

        if [[ ! -f "$path" ]]; then
            printf '%s%-12s%s %s\n' "$YELLOW" "MISSING" "$RESET" "$path"
            ((missing++)); continue
        fi

        actual=$(hash_file "$path")

        if [[ "$actual" == "$expected" ]]; then
            printf '%s%-12s%s %s\n' "$GREEN" "OK" "$RESET" "$path"
            ((ok++))
        else
            printf '%s%-12s%s %s\n' "$RED" "MODIFIED" "$RESET" "$path"
            printf '             expected: %s\n' "$expected"
            printf '             actual  : %s\n' "$actual"
            ((modified++))
        fi
    done

    echo
    echo "${BOLD}Integrity summary${RESET}"
    echo "  Unchanged : $ok"
    echo "  Modified  : $modified"
    echo "  Missing   : $missing"
    echo "  Unknown   : $unknown"

    # exit code: 0 clean, 1 something changed
    [[ $modified -eq 0 && $missing -eq 0 ]] && return 0 || return 1
}

# ------------------------------------------------------------ hash/compare --

cmd_hash() {
    [[ $# -gt 0 ]] || { echo "No files given." >&2; exit 1; }
    for f in "$@"; do
        printf '%-64s  %s\n' "$(hash_file "$f")" "$f"
    done
}

cmd_compare() {
    [[ $# -eq 2 ]] || { echo "compare needs exactly two files." >&2; exit 1; }
    local h1 h2
    h1=$(hash_file "$1"); h2=$(hash_file "$2")
    printf '%-64s  %s\n' "$h1" "$1"
    printf '%-64s  %s\n' "$h2" "$2"
    echo
    if [[ "$h1" == "$h2" && "$h1" != "MISSING" ]]; then
        echo "${GREEN}IDENTICAL${RESET} - the two files have the same $ALGO hash."
        return 0
    else
        echo "${RED}DIFFERENT${RESET} - the hashes do not match."
        return 1
    fi
}

cmd_list() {
    [[ -f "$BASELINE" ]] || { echo "No baseline at '$BASELINE'."; exit 1; }
    printf '%s%-64s %-8s %-20s %s%s\n' "$BOLD" "HASH" "ALGO" "RECORDED" "FILE" "$RESET"
    while IFS='|' read -r path algo hash stamp; do
        printf '%-64s %-8s %-20s %s\n' "$hash" "$algo" "$stamp" "$path"
    done < "$BASELINE"
}

# ------------------------------------------------------------------ main ----

while getopts ":a:b:h" opt; do
    case "$opt" in
        a) ALGO="$OPTARG" ;;
        b) BASELINE="$OPTARG" ;;
        h) usage ;;
        \?) echo "Unknown option -$OPTARG" >&2; usage ;;
    esac
done
shift $((OPTIND - 1))

[[ $# -ge 1 ]] || usage
action="$1"; shift

case "$action" in
    init)    cmd_init "$@" ;;
    check)   cmd_check "$@" ;;
    hash)    cmd_hash "$@" ;;
    compare) cmd_compare "$@" ;;
    list)    cmd_list ;;
    *)       echo "Unknown command: $action" >&2; usage ;;
esac
