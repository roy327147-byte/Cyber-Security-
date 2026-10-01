# cybersecurity

# cybersecurity Internship SAM AI Technologies  



# Cyber Security Project 

Bash implementations of three tasks.

## Task 1 — File Integrity Checker
Computes SHA-256/MD5 hashes, stores a baseline, and detects modified,
missing or unknown files.

    ./file_integrity_checker.sh init a.txt b.txt
    ./file_integrity_checker.sh check

## Task 2 — URL Safety Checker
Validates URL format and applies 13 offline heuristics (HTTPS, suspicious
keywords, raw-IP hosts, @ userinfo trick, punycode, abused TLDs, shorteners)
to produce a risk score.

    ./url_safety_checker.sh "http://example.com@192.168.0.6/secure-login.exe"

## Task 3 — Network Port Scanner
TCP connect scanner using bash's built-in /dev/tcp. Supports custom ranges
and writes a scan summary.

    ./port_scanner.sh -p 1-1024 localhost

> Only scan systems you own or have written permission to test.

## Requirements
Bash 4+, coreutils (`timeout`, `sha256sum`, `md5sum`). Tested on Linux.

## Author
Your Name — Debananda Roy 
