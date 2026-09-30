from __future__ import annotations
from datetime import datetime, timedelta
from pathlib import Path
import csv

USERS = ["alice", "bob", "charlie"]

def make_events(scenario: str):
    start = datetime(2026, 9, 1, 10, 0, 0)
    events = []
    for i, user in enumerate(USERS):
        events.append((start + timedelta(hours=i), "203.0.113.10", user, "Success", scenario))
    if scenario == "normal":
        return events
    if scenario == "bruteforce":
        base = start + timedelta(minutes=10)
        return events + [(base + timedelta(seconds=5*i), "198.51.100.8", "alice", "Failure", scenario) for i in range(12)]
    if scenario == "password_spray":
        base = start + timedelta(minutes=20)
        return events + [(base + timedelta(seconds=30*i), "198.51.100.9", user, "Failure", scenario) for i, user in enumerate(USERS)]
    if scenario == "night_attack":
        base = start.replace(hour=2)
        return events + [(base + timedelta(seconds=30*i), "198.51.100.8", "bob", "Failure", scenario) for i in range(6)]
    if scenario == "slow_evasion":
        base = start + timedelta(hours=2)
        return events + [(base + timedelta(minutes=2*i), "198.51.100.8", "charlie", "Failure", scenario) for i in range(6)]
    raise ValueError(scenario)

def write_all(path: str | Path):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp", "ip", "username", "status", "scenario"])
        for scenario in ("normal", "bruteforce", "password_spray", "night_attack", "slow_evasion"):
            for row in make_events(scenario):
                writer.writerow([x.isoformat() if isinstance(x, datetime) else x for x in row])

if __name__ == "__main__":
    write_all(Path(__file__).resolve().parents[1] / "data/events.csv")
