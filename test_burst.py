
import re
from collections import Counter
from datetime import datetime
from pathlib import Path

LOG_FILE = Path(__file__).with_name("test_burst.log")
WINDOW_SECONDS = 60
THRESHOLD = 10

pattern = re.compile(
    r'(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>\S+)(?:\s+[^"]*)?"\s+'
    r'(?P<status>\d{3})\s+\S+'
)

ip_times = {}

with LOG_FILE.open("r", encoding="utf-8") as file:
    for line in file:
        match = pattern.search(line)
        if not match:
            continue

        ip = match.group("ip")
        time_text = match.group("time")
        timestamp = datetime.strptime(
            time_text, "%d/%b/%Y:%H:%M:%S %z"
        )

        ip_times.setdefault(ip, []).append(timestamp)

print("=== Burst Detection Test ===")

for ip, times in ip_times.items():
    times.sort()
    max_count = 0
    left = 0

    for right in range(len(times)):
        while (
            times[right] - times[left]
        ).total_seconds() > WINDOW_SECONDS:
            left += 1

        max_count = max(max_count, right - left + 1)

    print(f"IP: {ip}")
    print(f"Requests: {len(times)}")
    print(f"Max requests in {WINDOW_SECONDS}s: {max_count}")

    if max_count >= THRESHOLD:
        print("Result: BURST DETECTED")
    else:
        print("Result: NORMAL")
