import csv
from datetime import datetime, timedelta
import collections

# Thresholds and Scores
ALERT_THRESHOLD = 4
SCORES = {
    "RAPID_ATTEMPTS": 3,
    "CONSECUTIVE_FAILURES": 2,
    "FOREIGN_IP": 2,
    "OUTSIDE_TOKYO": 1,
    "ABNORMAL_TIME": 1
}

def is_tokyo(ip):
    return ip.startswith("126.")

def is_japan(ip):
    return ip.startswith("126.") or ip.startswith("133.")

def get_time_score(timestamp):
    dt = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")
    if 1 <= dt.hour <= 5:
        return SCORES["ABNORMAL_TIME"]
    return 0

def get_location_score(ip):
    if not is_japan(ip):
        return SCORES["FOREIGN_IP"]
    if not is_tokyo(ip):
        return SCORES["OUTSIDE_TOKYO"]
    return 0

def analyze_logs(file_path):
    with open(file_path, "r") as f:
        reader = csv.DictReader(f)
        logs = list(reader)

    alerts = []
    
    # User-based tracking
    user_logs = collections.defaultdict(list)
    for log in logs:
        user_logs[log["Username"]].append(log)

    for username, entries in user_logs.items():
        for i, entry in enumerate(entries):
            score = 0
            reasons = []
            
            # 1. Time Check
            t_score = get_time_score(entry["Timestamp"])
            if t_score > 0:
                score += t_score
                reasons.append(f"Abnormal time ({entry['Timestamp']})")

            # 2. Location Check
            l_score = get_location_score(entry["IP_Address"])
            if l_score > 0:
                score += l_score
                reasons.append(f"Suspicious location ({entry['IP_Address']})")

            # 3. Consecutive Failures (5 within 5 mins)
            current_time = datetime.strptime(entry["Timestamp"], "%Y-%m-%d %H:%M:%S")
            recent_failures = 0
            for j in range(i, -1, -1):
                prev_entry = entries[j]
                prev_time = datetime.strptime(prev_entry["Timestamp"], "%Y-%m-%d %H:%M:%S")
                if current_time - prev_time > timedelta(minutes=5):
                    break
                if prev_entry["Status"] == "Failure":
                    recent_failures += 1
            
            if recent_failures >= 5:
                score += SCORES["CONSECUTIVE_FAILURES"]
                reasons.append(f"5+ consecutive failures within 5 mins")

            # 4. Rapid Attempts (10+ per minute)
            recent_attempts = 0
            for j in range(i, -1, -1):
                prev_entry = entries[j]
                prev_time = datetime.strptime(prev_entry["Timestamp"], "%Y-%m-%d %H:%M:%S")
                if current_time - prev_time > timedelta(minutes=1):
                    break
                recent_attempts += 1
            
            if recent_attempts >= 10:
                score += SCORES["RAPID_ATTEMPTS"]
                reasons.append(f"10+ attempts within 1 minute")

            if score >= ALERT_THRESHOLD:
                alerts.append({
                    "Timestamp": entry["Timestamp"],
                    "Username": username,
                    "IP": entry["IP_Address"],
                    "Score": score,
                    "Reasons": ", ".join(reasons)
                })

    return alerts

def main():
    log_file = "../data/login_logs.csv"
    print(f"Analyzing {log_file}...")
    alerts = analyze_logs(log_file)
    
    if not alerts:
        print("No anomalies detected.")
    else:
        print(f"Detected {len(alerts)} potential anomalies:")
        print("-" * 80)
        print(f"{'Timestamp':<20} | {'User':<12} | {'Score':<5} | {'Reasons'}")
        print("-" * 80)
        for alert in alerts:
            print(f"{alert['Timestamp']:<20} | {alert['Username']:<12} | {alert['Score']:<5} | {alert['Reasons']}")

if __name__ == "__main__":
    main()
