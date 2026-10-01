#!/usr/bin/env bash
#
# Task 2 - URL Safety Checker
#
# Takes a URL, validates its format, checks whether it uses HTTPS,
# looks for suspicious patterns/keywords, and reports SAFE or SUSPICIOUS.
#
# Usage:
#   ./url_safety_checker.sh https://example.com/login
#   ./url_safety_checker.sh -f urls.txt        # one URL per line
#   ./url_safety_checker.sh                    # interactive prompt
#
# Note: this is a static, offline heuristic check. It does not visit the URL
# and is not a substitute for a real reputation service.
#

set -uo pipefail

RED=$'\033[0;31m'; GREEN=$'\033[0;32m'; YELLOW=$'\033[0;33m'
BOLD=$'\033[1m'; RESET=$'\033[0m'

# Words that commonly appear in phishing / credential-harvesting URLs
SUSPICIOUS_KEYWORDS=(
    login signin verify verification account update secure security
    confirm password passwd credential banking bank paypal wallet
    bonus prize winner free gift claim urgent suspended locked
    recover unlock invoice billing refund crypto airdrop
)

# Free / commonly abused TLDs
RISKY_TLDS=( tk ml ga cf gq zip mov top xyz click work country )

# URL shorteners hide the real destination
SHORTENERS=(
    bit.ly tinyurl.com goo.gl t.co ow.ly is.gd buff.ly cutt.ly
    rebrand.ly shorturl.at rb.gy tiny.cc bit.do adf.ly
)

# ------------------------------------------------------------- validation ---

validate_url() {
    local url="$1"
    # scheme://host[:port][/path][?query][#fragment]
    [[ "$url" =~ ^[A-Za-z][A-Za-z0-9+.-]*://[^[:space:]/?#]+([/?#][^[:space:]]*)?$ ]]
}

get_scheme() { printf '%s' "${1%%://*}" | tr 'A-Z' 'a-z'; }

get_host() {
    local rest="${1#*://}"
    rest="${rest%%/*}"; rest="${rest%%\?*}"; rest="${rest%%#*}"
    rest="${rest##*@}"          # strip any userinfo
    rest="${rest%%:*}"          # strip port
    printf '%s' "$rest" | tr 'A-Z' 'a-z'
}

get_path() {
    local rest="${1#*://}"
    [[ "$rest" == */* ]] && printf '%s' "/${rest#*/}" || printf '/'
}

# ------------------------------------------------------------------ check ---

check_url() {
    local url="$1"
    local -a issues=() notes=()
    local score=0

    echo
    echo "${BOLD}URL:${RESET} $url"
    echo "------------------------------------------------------------"

    # 1. format
    if ! validate_url "$url"; then
        echo "  Format      : ${RED}INVALID${RESET}"
        echo
        echo "  Result: ${RED}${BOLD}INVALID URL${RESET} - not a well-formed URL."
        return 2
    fi
    echo "  Format      : ${GREEN}valid${RESET}"

    local scheme host path lower_url
    scheme=$(get_scheme "$url")
    host=$(get_host "$url")
    path=$(get_path "$url")
    lower_url=$(printf '%s' "$url" | tr 'A-Z' 'a-z')

    echo "  Scheme      : $scheme"
    echo "  Host        : $host"
    echo "  Path        : $path"

    # 2. HTTPS
    case "$scheme" in
        https) echo "  Encryption  : ${GREEN}HTTPS${RESET}" ;;
        http)  echo "  Encryption  : ${RED}HTTP (not encrypted)${RESET}"
               issues+=("Uses plain HTTP - traffic can be read or altered in transit")
               ((score += 2)) ;;
        *)     echo "  Encryption  : ${YELLOW}$scheme${RESET}"
               issues+=("Unusual scheme '$scheme'")
               ((score += 2)) ;;
    esac

    # 3. suspicious keywords
    local found_kw=()
    for kw in "${SUSPICIOUS_KEYWORDS[@]}"; do
        [[ "$lower_url" == *"$kw"* ]] && found_kw+=("$kw")
    done
    if ((${#found_kw[@]})); then
        issues+=("Suspicious keyword(s): ${found_kw[*]}")
        ((score += ${#found_kw[@]}))
    fi

    # 4. raw IP address instead of a domain name
    if [[ "$host" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; then
        issues+=("Host is a raw IP address instead of a domain name")
        ((score += 2))
    fi

    # 5. userinfo trick:  https://paypal.com@evil.site
    if [[ "${url#*://}" == *@* ]]; then
        issues+=("URL contains '@' - the real host is what comes after it")
        ((score += 3))
    fi

    # 6. punycode / IDN homograph
    if [[ "$host" == *xn--* ]]; then
        issues+=("Punycode domain (xn--) - may imitate a real brand")
        ((score += 2))
    fi

    # 7. excessive subdomains
    local dots="${host//[^.]/}"
    if (( ${#dots} >= 4 )); then
        issues+=("Deeply nested subdomains (${#dots} dots) - common in phishing")
        ((score += 1))
    fi

    # 8. risky TLD
    local tld="${host##*.}"
    for t in "${RISKY_TLDS[@]}"; do
        if [[ "$tld" == "$t" ]]; then
            issues+=("Top-level domain '.$tld' is frequently abused")
            ((score += 2)); break
        fi
    done

    # 9. URL shortener
    for s in "${SHORTENERS[@]}"; do
        if [[ "$host" == "$s" || "$host" == *".$s" ]]; then
            issues+=("Link shortener ($s) - final destination is hidden")
            ((score += 2)); break
        fi
    done

    # 10. hyphen-heavy lookalike domain
    local hyphens="${host//[^-]/}"
    if (( ${#hyphens} >= 3 )); then
        issues+=("Domain contains many hyphens - typical of lookalike domains")
        ((score += 1))
    fi

    # 11. non-standard port
    local hostport="${url#*://}"; hostport="${hostport%%/*}"
    if [[ "$hostport" =~ :([0-9]+)$ ]]; then
        local port="${BASH_REMATCH[1]}"
        if [[ "$port" != "80" && "$port" != "443" && "$port" != "8443" ]]; then
            issues+=("Non-standard port :$port")
            ((score += 1))
        fi
    fi

    # 12. very long URL
    if (( ${#url} > 100 )); then
        issues+=("Very long URL (${#url} chars) - often used to hide the real target")
        ((score += 1))
    fi

    # 13. risky download extension
    if [[ "$path" =~ \.(exe|scr|bat|cmd|msi|apk|jar|vbs|ps1|zip|rar)$ ]]; then
        issues+=("Path points directly to an executable/archive file")
        ((score += 2))
    fi

    # ---- report -------------------------------------------------------
    echo
    if ((${#issues[@]} == 0)); then
        echo "  Findings    : none"
    else
        echo "  Findings    :"
        for i in "${issues[@]}"; do echo "    - $i"; done
    fi

    echo
    printf '  Risk score  : %d\n' "$score"
    if (( score == 0 )); then
        echo "  Result: ${GREEN}${BOLD}SAFE${RESET} - no suspicious indicators found."
        return 0
    elif (( score <= 2 )); then
        echo "  Result: ${YELLOW}${BOLD}LOW RISK${RESET} - minor concerns, check before trusting."
        return 0
    else
        echo "  Result: ${RED}${BOLD}SUSPICIOUS${RESET} - do not enter credentials on this link."
        return 1
    fi
}

# ------------------------------------------------------------------- main ---

if [[ "${1:-}" == "-f" ]]; then
    file="${2:-}"
    [[ -f "$file" ]] || { echo "File not found: $file" >&2; exit 1; }
    flagged=0; total=0
    while read -r line; do
        [[ -z "${line// }" || "$line" == \#* ]] && continue
        ((total++))
        check_url "$line" || ((flagged++))
    done < "$file"
    echo
    echo "${BOLD}Scanned $total URL(s); $flagged flagged.${RESET}"
elif [[ $# -ge 1 ]]; then
    for u in "$@"; do check_url "$u"; done
else
    read -rp "Enter a URL to check: " url
    [[ -n "${url// }" ]] || { echo "No URL entered." >&2; exit 1; }
    check_url "$url"
fi
