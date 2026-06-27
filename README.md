# Python Log Parser — Brute Force Detector

A Python tool that parses Linux authentication logs, detects brute force activity, flags suspicious IPs, and identifies potential compromise indicators.

## What It Does

- Parses /var/log/auth.log or any custom log file
- Counts failed login attempts per IP address
- Flags IPs exceeding a configurable threshold as brute force suspects
- Extracts targeted usernames (root, admin, ubuntu etc)
- Detects potential compromise — IPs that failed repeatedly then successfully logged in
- Exports a structured JSON report

## Requirements

- Python 3
- No external libraries required — uses standard library only

## Setup

Clone the repository:

    git clone https://github.com/vaibhavkrishna12004/python-log-parser.git
    cd python-log-parser

## Usage

Basic scan using the included sample log:

    python3 log_parser.py

Custom log file and threshold:

    python3 log_parser.py --log /var/log/auth.log --threshold 10

Save JSON report to disk:

    python3 log_parser.py --log sample_auth.log --threshold 5 --report

## Arguments

| Argument    | Default          | Description                            |
|-------------|------------------|----------------------------------------|
| --log       | sample_auth.log  | Path to the auth log file              |
| --threshold | 5                | Failed attempts before brute force alert |
| --report    | False            | Save JSON report to disk               |

## Testing With Sample Log

A sample_auth.log file is included in the repo for testing. It contains:

- Brute force attempts from multiple IPs
- Two compromise indicators (failed attempts followed by successful login)
- Invalid user attempts
- Clean successful logins

Run against it directly:

    python3 log_parser.py --log sample_auth.log --threshold 5

## Sample Output

    LOG PARSER - BRUTE FORCE DETECTOR
    2026-06-27 09:00:00
    Log File : sample_auth.log
    Threshold: 5 failed attempts

    [+] Total failed login attempts : 19
    [+] Total successful logins     : 3
    [+] Unique IPs flagged          : 2

    [+] TOP OFFENDING IPs (threshold: 5):
        45.33.32.156         6 attempts <-- [ALERT] BRUTE FORCE SUSPECTED
        203.0.113.10         5 attempts <-- [ALERT] BRUTE FORCE SUSPECTED

    [+] MOST TARGETED USERNAMES:
        root                 6 attempts
        test                 5 attempts
        admin                3 attempts

    [!!] POTENTIAL COMPROMISE DETECTED:
         45.33.32.156 — 6 failed attempts before success
         203.0.113.10 — 5 failed attempts before success

## Why This Matters

Brute force detection is one of the most fundamental SOC tasks. This tool replicates the core detection logic that SIEM platforms apply to authentication logs — parsing, aggregating, thresholding, and flagging compromise indicators — built from scratch in Python.


