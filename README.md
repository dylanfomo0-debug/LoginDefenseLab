# Login Anomaly Detector

A rule-based intrusion detection system (IDS) designed to identify anomalous login behavior using User Behavior Analytics (UBA) logic.

## Overview
This project simulates a Host-based Intrusion Detection System (HIDS) that monitors login logs to detect suspicious activities such as brute force attacks, automated bot probing, and unusual login patterns (time/location).

## How It Works
The system follows a simple logic pipeline:
1. **Data Collection**: Parses login logs containing timestamps, IP addresses, usernames, and status.
2. **Baselining**: Compares new events against a defined baseline of "normal" behavior.
3. **Scoring**: Assigns risk scores based on deviations from the baseline.
4. **Alerting**: Triggers an alert if the cumulative risk score meets or exceeds the threshold.

### Detection Criteria
| Criteria | Condition | Score |
|----------|-----------|-------|
| Attempt Rate | 10+ attempts per minute | +3 |
| Attempt Result | 5 failures within 5 minutes | +2 |
| Location | Outside Japan | +2 |
| Location | Outside Tokyo (but in Japan) | +1 |
| Time | Login between 1 AM – 5 AM | +1 |

**Alert Threshold**: Cumulative Score ≥ 4

## Tech Stack
- **Language**: Python 3
- **Data Format**: CSV

## Project Structure
```
.
├── data/
│   └── login_logs.csv       # Generated login data
├── src/
│   ├── generate_data.py    # Script to create baseline and anomalous data
│   └── detector.py         # Main detection logic
└── README.md
```

## How to Run
1. **Generate Data**:
   ```bash
   cd src
   python3 generate_data.py
   ```
2. **Run Detector**:
   ```bash
   python3 detector.py
   ```

## Key Scenarios Detected
- **Brute Force**: Multiple failed attempts in a short window.
- **Automation**: Rapid bursts of login activity.
- **Geographic Anomaly**: Logins from unexpected locations.
- **Temporal Anomaly**: Logins during "deadzone" hours (1 AM - 5 AM).

## Limitations
- Rule-based logic (non-ML), which may require manual tuning of thresholds.
- Simplified geographic detection based on IP prefixes.
- Single-user focused behavioral patterns.
