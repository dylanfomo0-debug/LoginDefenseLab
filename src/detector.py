from __future__ import annotations
from collections import defaultdict, deque
from datetime import datetime, timedelta
import csv


def detect(rows, rate_limit=10, failure_limit=5):
    grouped = defaultdict(list)
    for row in rows:
        item = dict(row)
        item["dt"] = datetime.fromisoformat(item["timestamp"])
        grouped[item["username"]].append(item)
    alerts = []
    for user, entries in grouped.items():
        entries.sort(key=lambda x: x["dt"])
        window = deque()
        failures = deque()
        for entry in entries:
            dt = entry["dt"]
            window.append(entry)
            failures.append(entry)
            while window and dt - window[0]["dt"] > timedelta(minutes=1): window.popleft()
            while failures and dt - failures[0]["dt"] > timedelta(minutes=5): failures.popleft()
            reasons = []
            if len(window) >= rate_limit: reasons.append("rapid_attempts")
            if sum(x["status"] == "Failure" for x in failures) >= failure_limit: reasons.append("repeated_failures")
            if dt.hour in {1, 2, 3, 4, 5}: reasons.append("unusual_time")
            if entry["ip"] not in {"203.0.113.10"}: reasons.append("new_source")
            score = (3 if "rapid_attempts" in reasons else 0) + (2 if "repeated_failures" in reasons else 0) + (1 if "unusual_time" in reasons else 0) + (1 if "new_source" in reasons else 0)
            if score >= 4:
                alerts.append({"username": user, "timestamp": entry["timestamp"], "scenario": entry["scenario"], "score": score, "reasons": reasons})
    return alerts

def load(path):
    with open(path, newline="") as f: return list(csv.DictReader(f))
