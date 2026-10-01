#!/usr/bin/env bash
#
# Task 3 - Network Port Scanner
#
# Checks which TCP ports are open on a host you own or administer, using
# bash's built-in /dev/tcp redirection (no nmap required).
#
# Usage:
#   ./port_scanner.sh                       # scan localhost, common ports
#   ./port_scanner.sh 192.168.1.10          # scan a host, common ports
#   ./port_scanner.sh -p 1-1024 localhost   # custom port range
#   ./port_scanner.sh -p 22,80,443 host     # specific ports
#   ./port_scanner.sh -t 0.5 -a localhost   # timeout 0.5s, show closed ports too
#
# Options:
#   -p <ports>   port list/range: 80  |  20-25  |  22,80,443  |  1-100,3306
#   -t <sec>     connection timeout in seconds (default: 0.3)
#   -a           also list closed ports
#   -o <file>    write the summary to a file
#
# ONLY scan systems you own or have written permission to test.
# Unauthorised port scanning is illegal in many jurisdictions.
#

set -uo pipefail

TARGET="localhost"
PORT_SPEC=""
TIMEOUT="0.3"
SHOW_CLOSED=0
OUTFILE=""

RED=$'\033[0;31m'; GREEN=$'\033[0;32m'; YELLOW=$'\033[0;33m'
BOLD=$'\033[1m'; RESET=$'\033[0m'

COMMON_PORTS="21,22,23,25,53,67,68,69,80,110,123,135,139,143,161,389,443,445,\
465,514,587,631,993,995,1433,1521,1723,2049,2375,3000,3306,3389,5000,5432,\
5672,5900,6379,8000,8008,8080,8081,8443,8888,9000,9090,9200,11211,27017"

service_name() {
    case "$1" in
        21) echo "ftp" ;;        22) echo "ssh" ;;        23) echo "telnet" ;;
        25) echo "smtp" ;;       53) echo "dns" ;;        67|68) echo "dhcp" ;;
        69) echo "tftp" ;;       80) echo "http" ;;       110) echo "pop3" ;;
        123) echo "ntp" ;;       135) echo "msrpc" ;;     139) echo "netbios" ;;
        143) echo "imap" ;;      161) echo "snmp" ;;      389) echo "ldap" ;;
        443) echo "https" ;;     445) echo "smb" ;;       465) echo "smtps" ;;
        514) echo "syslog" ;;    587) echo "submission" ;; 631) echo "ipp" ;;
        993) echo "imaps" ;;     995) echo "pop3s" ;;     1433) echo "mssql" ;;
        1521) echo "oracle" ;;   1723) echo "pptp" ;;     2049) echo "nfs" ;;
        2375) echo "docker" ;;   3000) echo "dev-http" ;; 3306) echo "mysql" ;;
        3389) echo "rdp" ;;      5000) echo "upnp/flask" ;; 5432) echo "postgresql" ;;
        5672) echo "amqp" ;;     5900) echo "vnc" ;;      6379) echo "redis" ;;
        8000|8008|8080|8081) echo "http-alt" ;;           8443) echo "https-alt" ;;
        8888) echo "http-alt" ;; 9000) echo "http-alt" ;; 9090) echo "http-alt" ;;
        9200) echo "elasticsearch" ;; 11211) echo "memcached" ;;
        27017) echo "mongodb" ;;
        *) echo "unknown" ;;
    esac
}

# Expand "1-100,3306,8080" into a list of port numbers
expand_ports() {
    local spec="$1" part start end p
    IFS=',' read -ra parts <<< "$spec"
    for part in "${parts[@]}"; do
        part="${part// /}"
        [[ -z "$part" ]] && continue
        if [[ "$part" =~ ^([0-9]+)-([0-9]+)$ ]]; then
            start="${BASH_REMATCH[1]}"; end="${BASH_REMATCH[2]}"
            (( start > end )) && { p=$start; start=$end; end=$p; }
            for ((p = start; p <= end; p++)); do
                (( p >= 1 && p <= 65535 )) && echo "$p"
            done
        elif [[ "$part" =~ ^[0-9]+$ ]]; then
            (( part >= 1 && part <= 65535 )) && echo "$part"
        else
            echo "Invalid port specification: '$part'" >&2
            exit 1
        fi
    done
}

# TCP connect test using bash's /dev/tcp pseudo-device
probe_port() {
    local host="$1" port="$2"
    timeout "$TIMEOUT" bash -c "exec 3<>/dev/tcp/$host/$port" 2>/dev/null
}

# --------------------------------------------------------------- options ----

while getopts ":p:t:o:ah" opt; do
    case "$opt" in
        p) PORT_SPEC="$OPTARG" ;;
        t) TIMEOUT="$OPTARG" ;;
        o) OUTFILE="$OPTARG" ;;
        a) SHOW_CLOSED=1 ;;
        h) sed -n '2,25p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        \?) echo "Unknown option -$OPTARG" >&2; exit 1 ;;
        :)  echo "Option -$OPTARG needs an argument" >&2; exit 1 ;;
    esac
done
shift $((OPTIND - 1))

[[ $# -ge 1 ]] && TARGET="$1"
[[ -z "$PORT_SPEC" ]] && PORT_SPEC="$COMMON_PORTS"

command -v timeout >/dev/null 2>&1 || {
    echo "This script needs the 'timeout' command (coreutils)." >&2; exit 1; }

# Resolve the host so we fail fast on typos
RESOLVED=$(getent hosts "$TARGET" 2>/dev/null | awk '{print $1; exit}')
[[ -z "$RESOLVED" ]] && RESOLVED="$TARGET"

mapfile -t PORTS < <(expand_ports "$PORT_SPEC")
TOTAL=${#PORTS[@]}
(( TOTAL > 0 )) || { echo "No valid ports to scan." >&2; exit 1; }

# ------------------------------------------------------------------ scan ----

START=$(date '+%Y-%m-%d %H:%M:%S')
START_S=$SECONDS

echo "${BOLD}Port scan${RESET}"
echo "  Target   : $TARGET ($RESOLVED)"
echo "  Ports    : $TOTAL"
echo "  Timeout  : ${TIMEOUT}s"
echo "  Started  : $START"
echo
printf '%s%-8s %-14s %s%s\n' "$BOLD" "PORT" "STATE" "SERVICE" "$RESET"
printf '%s\n' "----------------------------------------"

OPEN_PORTS=()
CLOSED=0
SCANNED=0

for port in "${PORTS[@]}"; do
    ((SCANNED++))
    if probe_port "$RESOLVED" "$port"; then
        OPEN_PORTS+=("$port")
        printf '%-8s %sopen%s          %s\n' \
               "$port" "$GREEN" "$RESET" "$(service_name "$port")"
    else
        ((CLOSED++))
        (( SHOW_CLOSED )) && printf '%-8s %sclosed%s        %s\n' \
               "$port" "$RED" "$RESET" "$(service_name "$port")"
    fi
done

ELAPSED=$((SECONDS - START_S))

# --------------------------------------------------------------- summary ----

build_summary() {
    echo
    echo "${BOLD}Scan summary${RESET}"
    echo "  Target        : $TARGET ($RESOLVED)"
    echo "  Ports scanned : $SCANNED"
    echo "  Open          : ${#OPEN_PORTS[@]}"
    echo "  Closed/filtered: $CLOSED"
    echo "  Duration      : ${ELAPSED}s"
    echo "  Finished      : $(date '+%Y-%m-%d %H:%M:%S')"
    echo
    if ((${#OPEN_PORTS[@]})); then
        echo "  Open ports:"
        for p in "${OPEN_PORTS[@]}"; do
            printf '    %-6s %s\n' "$p" "$(service_name "$p")"
        done
        echo
        echo "  ${YELLOW}Review each open port: close or firewall anything"
        echo "  that does not need to be reachable.${RESET}"
    else
        echo "  No open ports found in the scanned range."
    fi
}

build_summary

if [[ -n "$OUTFILE" ]]; then
    build_summary | sed 's/\x1b\[[0-9;]*m//g' > "$OUTFILE"
    echo
    echo "Summary written to $OUTFILE"
fi
