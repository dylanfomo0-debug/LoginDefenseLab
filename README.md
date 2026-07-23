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

## Background Theory

### What is an IDS?
An Intrusion Detection System (IDS) is designed to detect unauthorized or suspicious activity on a network or device. There are two main types:

- **Signature-based**: Matches activity against a database of known attack patterns. Requires constant updates and is weak against newer, unknown attacks.
- **Anomaly-based (used in this project)**: Builds a baseline of "normal" behavior using machine learning or statistics and flags anything that deviates from that baseline. Can catch new/unknown attacks but is more prone to false positives.

### Why Anomaly Detection for Logins?
Login events are highly structured and rich in patterns, making them ideal for baselining user behavior. Common attack patterns like brute force and credential stuffing leave clear behavioral traces that deviate from normal baselines. A lightweight anomaly detector can be realistically built and tested in a home environment.

### What the System Watches (Log Data)
- **Who**: Username attempting to log in
- **Where**: IP address / geographic location
- **When**: Timestamps
- **Status**: Success/failure

Key suspicious patterns focused on:
- Repeated failures followed by a success
- Logins from unusual locations
- Sudden spikes in login traffic
- Activity at abnormal hours

### How Detection Works (UBA Logic)
1. **Collect and parse login log data**.
2. **Build a behavioral baseline per user** (normal login times, locations, frequency).
3. **Continuously compare new events against the baseline**.
4. **Assign a risk score to deviations**.
5. **Trigger an alert** if the score passes a set threshold.

### Scope: HIDS (Host-based)
This project focuses on a Host-based Intrusion Detection System (HIDS), monitoring traffic to and from one specific machine or service. This scope is realistic and manageable for a personal/home project.

### Key Challenges
- **False positives**: Flagging normal behavior as suspicious (e.g., user logs in from a new device).
- **False negatives**: Missing an actual attack that blends into normal patterns.

### References
- IBM, What is Intrusion Detection System (IDS)?
- Fortinet, Intrusion Detection System (IDS) Explained
- Splunk, Introduction to Log Analysis
- TryHackMe, Security Log Analysis Basics
- SANS Institute, User Behavior Analytics (UBA) Overview
