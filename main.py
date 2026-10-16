
from collections import Counter

# 練習用のアクセスログ
logs = [
    ("192.0.2.10", 200, "/"),
    ("192.0.2.10", 200, "/login"),
    ("192.0.2.20", 404, "/admin"),
    ("192.0.2.20", 404, "/backup.zip"),
    ("192.0.2.20", 404, "/config.php"),
    ("192.0.2.30", 200, "/products"),
    ("192.0.2.40", 403, "/admin"),
]

print("=== Security Log Analyzer ===")

# IPアドレスごとのアクセス数
ip_counts = Counter(ip for ip, status, path in logs)

print("\n[アクセス数]")
for ip, count in ip_counts.most_common():
    print(f"{ip}: {count} requests")

# 404エラーの検出
print("\n[404エラー]")
for ip, status, path in logs:
    if status == 404:
        print(f"IP={ip} path={path}")

# 確認が必要なパスの検出
print("\n[疑わしいパス]")
suspicious_keywords = ("admin", "backup", "config")

for ip, status, path in logs:
    if any(keyword in path.lower() for keyword in suspicious_keywords):
        print(f"要確認: IP={ip} path={path}")
