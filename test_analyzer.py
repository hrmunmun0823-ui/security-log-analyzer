
import re
import unittest
from datetime import datetime
from collections import Counter
from pathlib import Path
from tempfile import TemporaryDirectory


LOG_PATTERN = re.compile(
    r'(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>\S+)(?:\s+[^"]*)?"\s+'
    r'(?P<status>\d{3})\s+\S+'
)


def analyze_log(log_text, window_seconds=60, threshold=10):
    ip_times = {}
    status_counts = Counter()
    unparsed_lines = 0

    for line in log_text.splitlines():
        if not line.strip():
            continue

        match = LOG_PATTERN.search(line)

        if not match:
            unparsed_lines += 1
            continue

        try:
            timestamp = datetime.strptime(
                match.group("time"),
                "%d/%b/%Y:%H:%M:%S %z"
            )
        except ValueError:
            unparsed_lines += 1
            continue

        ip = match.group("ip")
        status = int(match.group("status"))

        ip_times.setdefault(ip, []).append(timestamp)
        status_counts[status] += 1

    burst_ips = set()
    max_requests = {}

    for ip, times in ip_times.items():
        times.sort()
        left = 0
        max_count = 0

        for right in range(len(times)):
            while (
                times[right] - times[left]
            ).total_seconds() > window_seconds:
                left += 1

            max_count = max(max_count, right - left + 1)

        max_requests[ip] = max_count

        if max_count >= threshold:
            burst_ips.add(ip)

    return {
        "total_requests": sum(len(v) for v in ip_times.values()),
        "unparsed_lines": unparsed_lines,
        "status_counts": status_counts,
        "ip_counts": {
            ip: len(times) for ip, times in ip_times.items()
        },
        "max_requests": max_requests,
        "burst_ips": burst_ips,
    }


def make_log(ip, second, status=200):
    return (
        f'{ip} - - [16/Oct/2026:10:00:{second:02d} +0900] '
        f'"GET / HTTP/1.1" {status} 512'
    )


class TestSecurityLogAnalyzer(unittest.TestCase):

    def test_normal_log(self):
        log = "\n".join([
            make_log("192.0.2.10", 0, 200),
            make_log("192.0.2.10", 5, 404),
        ])

        result = analyze_log(log)

        self.assertEqual(result["total_requests"], 2)
        self.assertEqual(result["unparsed_lines"], 0)
        self.assertEqual(result["ip_counts"]["192.0.2.10"], 2)
        self.assertEqual(result["status_counts"][200], 1)
        self.assertEqual(result["status_counts"][404], 1)
        self.assertEqual(len(result["burst_ips"]), 0)

    def test_burst_detection(self):
        log = "\n".join(
            make_log("198.51.100.77", second)
            for second in range(10)
        )

        result = analyze_log(log)

        self.assertEqual(result["total_requests"], 10)
        self.assertEqual(result["max_requests"]["198.51.100.77"], 10)
        self.assertIn("198.51.100.77", result["burst_ips"])

    def test_invalid_log(self):
        log = "this is not a valid access log"

        result = analyze_log(log)

        self.assertEqual(result["total_requests"], 0)
        self.assertEqual(result["unparsed_lines"], 1)
        self.assertEqual(len(result["burst_ips"]), 0)

    def test_exactly_60_seconds(self):
        log = "\n".join([
            make_log("192.0.2.20", 0),
            make_log("192.0.2.20", 59),
        ])

        result = analyze_log(log)

        self.assertEqual(result["max_requests"]["192.0.2.20"], 2)
        self.assertNotIn("192.0.2.20", result["burst_ips"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
