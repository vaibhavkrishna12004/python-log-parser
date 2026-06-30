import re
import json
import argparse
import urllib.request
from collections import Counter
from datetime import datetime

# CLI Arguments
parser = argparse.ArgumentParser(description="Log Parser - Brute Force Detector")
parser.add_argument("--log", default="sample_auth.log", help="Path to auth log file")
parser.add_argument("--threshold", type=int, default=5, help="Failed attempts before brute force alert")
parser.add_argument("--report", action="store_true", help="Save JSON report to disk")
parser.add_argument("--geo", action="store_true", help="Geolocate flagged IP addresses")
args = parser.parse_args()

LOG_FILE = args.log
THRESHOLD = args.threshold
TIMESTAMP = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
REPORT_FILENAME = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

# Geolocation Helper
def is_private_ip(ip):
    octets = ip.split(".")
    if octets[0] == "10":
        return True
    if octets[0] == "192" and octets[1] == "168":
        return True
    if octets[0] == "172" and 16 <= int(octets[1]) <= 31:
        return True
    if octets[0] == "127":
        return True
    return False

def geolocate(ip):
    if is_private_ip(ip):
        return "Private/Local Network"
    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,country,city"
        with urllib.request.urlopen(url, timeout=5) as response:
            data = json.loads(response.read().decode())
        if data.get("status") == "success":
            city = data.get("city", "Unknown")
            country = data.get("country", "Unknown")
            return f"{city}, {country}"
        return "Location unknown"
    except Exception:
        return "Lookup failed (check connection)"

# Header
print("=" * 50)
print("   LOG PARSER - BRUTE FORCE DETECTOR")
print(f"   {TIMESTAMP}")
print(f"   Log File : {LOG_FILE}")
print(f"   Threshold: {THRESHOLD} failed attempts")
print("=" * 50)

# Parse Log
failed_attempts = []
successful_logins = []
failed_ips = []
failed_users = []
successful_ips = []

try:
    with open(LOG_FILE, "r") as f:
        for line in f:

            if "Failed password" in line:
                failed_attempts.append(line.strip())

                ip_match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', line)
                if ip_match:
                    failed_ips.append(ip_match.group(1))

                user_match = re.search(r'for (?:invalid user )?(\S+) from', line)
                if user_match:
                    failed_users.append(user_match.group(1))

            if "Accepted password" in line or "Accepted publickey" in line:
                successful_logins.append(line.strip())

                ip_match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', line)
                if ip_match:
                    successful_ips.append(ip_match.group(1))

except FileNotFoundError:
    print(f"\n[ERROR] Log file not found: {LOG_FILE}")
    exit()

# Analysis
ip_counts = Counter(failed_ips)
user_counts = Counter(failed_users)
brute_force_ips = {ip: count for ip, count in ip_counts.items() if count >= THRESHOLD}
compromise_indicators = [ip for ip in successful_ips if ip in brute_force_ips]

geo_data = {}
if args.geo:
    print("\n[+] Geolocating flagged IPs...")
    for ip in brute_force_ips:
        geo_data[ip] = geolocate(ip)

# Output
print(f"\n[+] Total failed login attempts : {len(failed_attempts)}")
print(f"[+] Total successful logins     : {len(successful_logins)}")
print(f"[+] Unique IPs flagged          : {len(brute_force_ips)}")

print(f"\n[+] TOP OFFENDING IPs (threshold: {THRESHOLD}):")
for ip, count in ip_counts.most_common(10):
    flag = " <-- [ALERT] BRUTE FORCE SUSPECTED" if count >= THRESHOLD else ""
    location = ""
    if args.geo and ip in geo_data:
        location = f"  [{geo_data[ip]}]"
    print(f"    {ip:20} {count} attempts{flag}{location}")

print(f"\n[+] MOST TARGETED USERNAMES:")
for user, count in user_counts.most_common(5):
    print(f"    {user:20} {count} attempts")

print(f"\n[+] RECENT FAILED ATTEMPTS (last 5):")
for line in failed_attempts[-5:]:
    print(f"    {line}")

if compromise_indicators:
    print(f"\n[!!] POTENTIAL COMPROMISE DETECTED:")
    print(f"     The following IPs had repeated failures then a successful login:")
    for ip in compromise_indicators:
        loc = f" ({geo_data[ip]})" if args.geo and ip in geo_data else ""
        print(f"     {ip} — {brute_force_ips[ip]} failed attempts before success{loc}")
else:
    print(f"\n[+] No compromise indicators detected.")

# JSON Report
if args.report:
    report = {
        "scan_time": TIMESTAMP,
        "log_file": LOG_FILE,
        "threshold": THRESHOLD,
        "summary": {
            "total_failed": len(failed_attempts),
            "total_successful": len(successful_logins),
            "flagged_ips": len(brute_force_ips)
        },
        "brute_force_ips": dict(ip_counts.most_common(10)),
        "targeted_usernames": dict(user_counts.most_common(10)),
        "compromise_indicators": compromise_indicators,
        "geolocation": geo_data if args.geo else "not requested"
    }

    with open(REPORT_FILENAME, "w") as f:
        json.dump(report, f, indent=4)

    print(f"\n[+] Report saved to: {REPORT_FILENAME}")

print("\n" + "=" * 50)
print("   SCAN COMPLETE")
print("=" * 50)
