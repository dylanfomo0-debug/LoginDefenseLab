from pathlib import Path
from .generate_scenarios import write_all
from .detector import detect, load

ROOT = Path(__file__).resolve().parents[1]

def main():
    path = ROOT / "data/events.csv"
    write_all(path)
    rows = load(path)
    alerts = detect(rows)
    scenarios = ["normal", "bruteforce", "password_spray", "night_attack", "slow_evasion"]
    print("Scenario             Alerts")
    print("-" * 32)
    for s in scenarios:
        count = sum(a["scenario"] == s for a in alerts)
        print(f"{s:<20} {count}")
    print("\nInterpretation: slow_evasion is intentionally difficult; a zero-alert result is a finding, not a bug.")

if __name__ == "__main__": main()
