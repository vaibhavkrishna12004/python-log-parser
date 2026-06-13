# Log Parser


A Python-based tool for analyzing Linux authentication logs and detecting potential brute-force attacks. The parser processes auth.log files to identify failed and successful SSH login attempts, extract source IP addresses, rank suspicious activity, and flag IPs that exceed a configurable failed login threshold. It also provides a summary of authentication events and recent failed login attempts to support incident response and security investigations. Built using Python, regular expressions, and collections.Counter, this project demonstrates practical log analysis, automation, and defensive security concepts. It can also be integrated with my Linux Incident Response Toolkit as part of a broader workflow for investigating Linux systems after a security incident
Python tool that analyzes Linux auth logs, detects brute-force attacks, and identifies suspicious login activity. ⭐
Python Log Parser & Brute Force Detector

A lightweight Python tool that analyzes Linux authentication logs to identify failed and successful login attempts, detect potential brute-force attacks, and generate actionable security insights.

## Features

- Parses Linux authentication logs ("auth.log")
- Counts successful and failed login attempts
- Extracts and ranks source IP addresses by failed login frequency
- Detects potential brute-force attacks using a configurable threshold
- Displays the most recent failed login attempts for quick investigation

## How It Works

The script processes each line of the authentication log and searches for common SSH authentication events:

- Failed password — Records failed SSH login attempts.
- Accepted password / Accepted publickey — Identifies successful authentications.

Using Python's "re" module, the script extracts IP addresses from log entries, while "collections.Counter" ranks them based on the number of failed attempts. By default, any IP address with more than 5 failed login attempts is flagged as a potential brute-force source.

## Usage

python3 log_parser.py

## Sample Output

<img width="1920" height="1045" alt="Screenshot_2026-06-13_15-13-46" src="https://github.com/user-attachments/assets/f147a013-ced4-49a3-8f4f-72a5367ddf37" />


Integration

This project is designed to integrate seamlessly with the Linux Incident Response Toolkit, allowing it to be used as part of a broader incident response workflow for automated log analysis and threat detection.


# Tools Used

- Python 3
- "re" – Regular expression-based IP extraction
- "collections.Counter" – Frequency analysis
- "datetime" – Timestamp generation

## Purpose

This project was developed to strengthen practical skills in Python, Linux system analysis, and security automation. It demonstrates the use of scripting to analyze authentication logs and identify suspicious login activity, reflecting real-world tasks performed in Security Operations Centers (SOC) and incident response environments.
