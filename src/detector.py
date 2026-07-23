import csv
from collections import defaultdict, deque
from datetime import datetime, timedelta

ALERT_THRESHOLD = 4

SCORES = {
    "RAPID_ATTEMPTS": 3,
    "CONSECUTIVE_FAILURES": 2,
    "FOREIGN_IP": 2,
    "OUTSIDE_TOKYO": 1,
    "ABNORMAL_TIME": 1,
}

IP_LOCATIONS = {
    "133.12.45.1": "Tokyo",
    "133.12.45.2": "Tokyo",
    "192.168.1.1": "Japan",
    "85.214.132.117": "Germany",
}


def check_time(dt):
    """Return score if login occurs between 1AM and 5AM."""
    if 1 <= dt.hour <= 5:
        return SCORES["ABNORMAL_TIME"], "Abnormal login time"
    return 0, None


def check_location(ip):
    """Check login location using simplified Geo-IP database."""
    location = IP_LOCATIONS.get(ip, "Unknown")
    if location == "Tokyo":
        return 0, None
    elif location == "Japan":
        return SCORES["OUTSIDE_TOKYO"], "Outside Tokyo"
    return SCORES["FOREIGN_IP"], f"Foreign IP ({location})"


def check_attempt_rate(window, dt):
    """Detect 10+ attempts within one minute."""
    attempts = sum(1 for t, _ in window if dt - t <= timedelta(minutes=1))
    if attempts >= 10:
        return SCORES["RAPID_ATTEMPTS"], "10+ attempts within 1 minute"
    return 0, None


def check_consecutive_failures(window):
    """Detect 5 consecutive failed logins."""
    consecutive = 0
    for _, status in reversed(window):
        if status == "Failure":
            consecutive += 1
            if consecutive >= 5:
                return SCORES["CONSECUTIVE_FAILURES"], "5 consecutive failures"
        else:
            break
    return 0, None


def analyze_logs(file_path):
    alerts = []
    user_logs = defaultdict(list)

    with open(file_path, "r") as f:
        reader = csv.DictReader(f)
        for row in reader:
            row["Timestamp"] = datetime.strptime(row["Timestamp"], "%Y-%m-%d %H:%M:%S")
            user_logs[row["Username"]].append(row)

    for username, entries in user_logs.items():
        entries.sort(key=lambda x: x["Timestamp"])
        recent_window = deque()

        for entry in entries:
            dt = entry["Timestamp"]
            score, reasons = 0, []

            recent_window.append((dt, entry["Status"]))
            while recent_window and dt - recent_window[0][0] > timedelta(minutes=5):
                recent_window.popleft()

            # Rule checks
            for check_func, args in [
                (check_time, (dt,)),
                (check_location, (entry["IP_Address"],)),
                (check_attempt_rate, (recent_window, dt)),
                (check_consecutive_failures, (recent_window,)),
            ]:
                s, r = check_func(*args)
                score += s
                if r:
                    reasons.append(r)

            if score >= ALERT_THRESHOLD:
                alerts.append({
                    "Timestamp": dt.strftime("%Y-%m-%d %H:%M:%S"),
                    "Username": username,
                    "IP": entry["IP_Address"],
                    "Score": score,
                    "Reasons": ", ".join(reasons),
                })

    return alerts


def main():
    log_file = "../data/login_logs.csv"
    print(f"Analyzing {log_file}...\n")
    alerts = analyze_logs(log_file)

    if not alerts:
        print("No anomalies detected.")
        return

    print(f"Detected {len(alerts)} potential anomalies\n")
    print("-" * 95)
    print(f"{'Timestamp':<20} | {'User':<10} | {'Score':<5} | Reasons")
    print("-" * 95)

    for alert in alerts:
        print(f"{alert['Timestamp']:<20} | {alert['Username']:<10} | {alert['Score']:<5} | {alert['Reasons']}")


if __name__ == "__main__":
    main()
