# Python Log Parser — Brute Force Detector

A Python tool that parses Linux authentication logs, detects brute force activity, flags suspicious IPs, geolocates attackers, and identifies potential compromise indicators.

## What It Does

- Parses /var/log/auth.log or any custom log file
- Counts failed login attempts per IP address
- Flags IPs exceeding a configurable threshold as brute force suspects
- Extracts targeted usernames (root, admin, ubuntu etc)
- Geolocates flagged IPs to show the country and city of origin
- Detects potential compromise — IPs that failed repeatedly then successfully logged in
- Exports a structured JSON report

## Requirements

- Python 3
- No external libraries required — uses standard library only
- Internet connection required only for the --geo feature

## Setup

Clone the repository: https://github.com/vaibhavkrishna12004/python-log-parser/blob/a0c79a9632ff775d5f22e365ff19b3d363ff183f/log_parser.py

 cd python-log-parser
  

## Usage

Basic scan using the included sample log:

    python3 log_parser.py

Custom log file and threshold:

    python3 log_parser.py --log /var/log/auth.log --threshold 10

Geolocate flagged IP addresses:

    python3 log_parser.py --log sample_auth.log --threshold 5 --geo

Save JSON report to disk:

    python3 log_parser.py --log sample_auth.log --threshold 5 --report

Combine flags:

    python3 log_parser.py --log sample_auth.log --threshold 5 --geo --report

## Arguments

| Argument    | Default          | Description                              |
|-------------|------------------|------------------------------------------|
| --log       | sample_auth.log  | Path to the auth log file                |
| --threshold | 5                | Failed attempts before brute force alert |
| --geo       | False            | Geolocate flagged IP addresses           |
| --report    | False            | Save JSON report to disk                 |

## About the --geo Flag

Geolocation is optional and only runs when --geo is passed. It looks up each flagged IP using the free ip-api.com service and returns the city and country of origin. Private and local IP ranges (10.x, 192.168.x, 172.16–31.x, 127.x) are labelled as "Private/Local Network" since they have no public geographic location. This feature requires an internet connection — the rest of the tool works fully offline.

Location data matters in a real SOC context: brute force traffic from unexpected regions is often the first signal analysts use to identify coordinated attacks or decide whether to block entire IP ranges.

## Testing With Sample Log

A sample_auth.log file is included in the repo for testing. It contains:

- Brute force attempts from multiple IPs
- Compromise indicators (failed attempts followed by successful login)
- Invalid user attempts
- Clean successful logins

Run against it directly:

    python3 log_parser.py --log sample_auth.log --threshold 5 --geo

## Sample Output

    LOG PARSER - BRUTE FORCE DETECTOR
    2026-06-30 09:00:00
    Log File : sample_auth.log
    Threshold: 5 failed attempts

    [+] Total failed login attempts : 19
    [+] Total successful logins     : 3
    [+] Unique IPs flagged          : 2

    [+] TOP OFFENDING IPs (threshold: 5):
        45.33.32.156         6 attempts <-- [ALERT] BRUTE FORCE SUSPECTED  [Frankfurt, Germany]
        203.0.113.10         5 attempts <-- [ALERT] BRUTE FORCE SUSPECTED  [Singapore, Singapore]

    [+] MOST TARGETED USERNAMES:
        root                 6 attempts
        test                 5 attempts
        admin                3 attempts

    [!!] POTENTIAL COMPROMISE DETECTED:
         45.33.32.156 — 6 failed attempts before success (Frankfurt, Germany)
         203.0.113.10 — 5 failed attempts before success (Singapore, Singapore)

## Why This Matters

Brute force detection is one of the most fundamental SOC tasks. This tool replicates the core detection logic that SIEM platforms apply to authentication logs parsing, aggregating, thresholding, geolocating, and flagging compromise indicators built from scratch in Python.

## Output Files

Each run with --csv or --report creates a timestamped file (flagged_ips_*.csv or report_*.json). These are disposable output artifacts, not part of the tool. To clear them:

    rm flagged_ips_*.csv report_*.json



