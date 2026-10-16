
import re
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

# =========================
# 設定
# =========================

LOG_FILE = Path(__file__).with_name("access.log")

BURST_WINDOW_SECONDS = 60
BURST_REQUEST_THRESHOLD = 10

SUSPICIOUS_PATHS = {
    "/admin": 2,
    "/wp-admin": 2,
    "/backup.zip": 3,
    "/.env": 3,
    "/phpmyadmin": 3,
}

# Apache形式のアクセスログを解析する
LOG_PATTERN = re.compile(
    r'(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>\S+)(?:\s+[^"]*)?"\s+'
    r'(?P<status>\d{3})\s+\S+'
)


def main():
    if not LOG_FILE.exists():
        print(f"ログファイルが見つかりません: {LOG_FILE}")
        print("access.logをmain.pyと同じフォルダに置いてください。")
        return

    status_counts = Counter()
    ip_counts = Counter()
    ip_errors = Counter()
    ip_scores = Counter()
    ip_findings = defaultdict(list)
    ip_timestamps = defaultdict(list)

    total_requests = 0
    unparsed_lines = 0

    # =========================
    # ログ読み込み・解析
    # =========================

    with LOG_FILE.open("r", encoding="utf-8") as file:
        for line_number, line in enumerate(file, start=1):
            line = line.strip()

            if not line:
                continue

            match = LOG_PATTERN.search(line)

            if not match:
                unparsed_lines += 1
                print(f"[解析失敗] {line_number}行目")
                continue

            ip = match.group("ip")
            timestamp_text = match.group("time")
            path = match.group("path").split("?")[0]

            try:
                timestamp = datetime.strptime(
                    timestamp_text,
                    "%d/%b/%Y:%H:%M:%S %z"
                )
            except ValueError:
                unparsed_lines += 1
                print(f"[時刻解析失敗] {line_number}行目")
                continue

            status = int(match.group("status"))

            total_requests += 1
            ip_counts[ip] += 1
            status_counts[status] += 1
            ip_timestamps[ip].append(timestamp)

            # エラー応答を集計
            if status >= 400:
                ip_errors[ip] += 1

            # 不審なパスを検知
            for suspicious_path, points in SUSPICIOUS_PATHS.items():
                if path == suspicious_path:
                    ip_scores[ip] += points
                    ip_findings[ip].append(
                        f"path={path} (+{points})"
                    )
                    break

            # HTTPステータスによる加点
            if status == 404:
                ip_scores[ip] += 1
                ip_findings[ip].append("HTTP 404 (+1)")
            elif status == 403:
                ip_scores[ip] += 2
                ip_findings[ip].append("HTTP 403 (+2)")
            elif status >= 500:
                ip_scores[ip] += 2
                ip_findings[ip].append(
                    f"HTTP {status} (+2)"
                )

    # =========================
    # 基本集計
    # =========================

    print("\n=== Security Log Analyzer ===")
    print(f"Total requests: {total_requests}")
    print(f"Unparsed lines: {unparsed_lines}")

    print("\n=== Status Codes ===")
    for status, count in sorted(status_counts.items()):
        print(f"{status}: {count}")

    print("\n=== IP Request Counts ===")
    for ip, count in ip_counts.most_common():
        print(f"{ip}: {count} requests")

    # =========================
    # リスク評価
    # =========================

    print("\n=== Security Risk Assessment ===")

    for ip, request_count in ip_counts.most_common():
        errors = ip_errors[ip]
        error_rate = errors / request_count * 100
        score = ip_scores[ip]

        # エラー率による評価
        if error_rate >= 80:
            score += 3
            ip_findings[ip].append(
                "Error rate >= 80% (+3)"
            )
        elif error_rate >= 50:
            score += 2
            ip_findings[ip].append(
                "Error rate >= 50% (+2)"
            )

        # 短時間の大量アクセスを検知
        timestamps = sorted(ip_timestamps[ip])
        burst_detected = False
        max_requests_in_window = 0

        left = 0
        for right in range(len(timestamps)):
            while (
                timestamps[right] - timestamps[left]
            ).total_seconds() > BURST_WINDOW_SECONDS:
                left += 1

            window_count = right - left + 1
            max_requests_in_window = max(
                max_requests_in_window,
                window_count
            )

            if window_count >= BURST_REQUEST_THRESHOLD:
                burst_detected = True

        if burst_detected:
            score += 5
            ip_findings[ip].append(
                f"At least {BURST_REQUEST_THRESHOLD} requests "
                f"within {BURST_WINDOW_SECONDS} seconds (+5)"
            )

        # 優先度を決定
        if score >= 8:
            priority = "HIGH"
        elif score >= 3:
            priority = "MEDIUM"
        else:
            priority = "LOW"

        print(f"\nIP={ip}")
        print(f"  Requests: {request_count}")
        print(f"  Error responses: {errors}")
        print(f"  Error rate: {error_rate:.1f}%")
        print(
            f"  Max requests in "
            f"{BURST_WINDOW_SECONDS}s: {max_requests_in_window}"
        )
        print(f"  Risk score: {score}")
        print(f"  Priority: {priority}")

        if ip_findings[ip]:
            for finding in ip_findings[ip]:
                print(f"  Finding: {finding}")
        else:
            print("  Finding: No configured indicators")

    print("\n=== Analysis Complete ===")
    print("A high score is a signal for investigation,")
    print("not proof of a cyberattack.")


if __name__ == "__main__":
    main()
