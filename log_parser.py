import re
from collections import Counter
from datetime import datetime

LOG_FILE = "sample_auth.log"
THRESHOLD = 5

print("=" * 40)
print("  LOG PARSER - BRUTE FORCE DETECTOR")
print(f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
print("=" * 40)

failed_attempts = []
successful_logins = []
failed_ips = []

try:
    with open(LOG_FILE, "r") as f:
        for line in f:
            if "Failed password" in line:
                failed_attempts.append(line.strip())
                ip_match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', line)
                if ip_match:
                    failed_ips.append(ip_match.group(1))
            if "Accepted password" in line or "Accepted publickey" in line:
                successful_logins.append(line.strip())

except FileNotFoundError:
    print(f"[ERROR] Log file not found: {LOG_FILE}")
    exit()

print(f"\n[+] Total failed login attempts: {len(failed_attempts)}")
print(f"[+] Total successful logins: {len(successful_logins)}")

ip_counts = Counter(failed_ips)

print(f"\n[+] TOP OFFENDING IPs:")
for ip, count in ip_counts.most_common(10):
    flag = " <-- [ALERT] BRUTE FORCE SUSPECTED" if count >= THRESHOLD else ""
    print(f"    {ip} - {count} attempts{flag}")

print("\n[+] RECENT FAILED ATTEMPTS (last 5):")
for line in failed_attempts[-5:]:
    print(f"    {line}")

print("\n" + "=" * 40)
print("  SCAN COMPLETE")
print("=" * 40)
