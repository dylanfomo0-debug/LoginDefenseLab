# How Easily Can a Login Anomaly Detector Be Fooled?

A controlled experiment that generates normal login behavior and several synthetic attack patterns, then measures where a rule-based detector succeeds and fails.

## Research question

> How do attack speed and behavior change the false-positive and false-negative profile of a simple login detector?

## Scenarios

- `normal` — ordinary successful logins
- `bruteforce` — rapid failures from one source
- `password_spray` — one password pattern across users
- `night_attack` — activity during unusual hours
- `slow_evasion` — failures deliberately spaced below the rate threshold

## Run it

```bash
python3 -m src.evaluate
python3 -m unittest discover -s tests -v
```

All events are generated locally. No accounts, networks, or real IP reputation services are used.

## Curiosity prompts

- Can slowing an attack below a threshold evade detection?
- Does a low threshold catch more attacks but create more false alarms?
- Which combination of weak signals is most useful?
- What should a defender do when the detector is uncertain?

## Limitations

This is not a production IDS. It uses toy thresholds, synthetic users, and simplified IP/location behavior. The purpose is to practice experimental design and defensive reasoning.
## Project reflection

- **What I personally implemented:** I wrote the synthetic scenario generator, sliding-window login analysis, failure counting, risk-score rules, alert output, benchmark, and unit tests.
- **One actual result:** The published tests all passed (**3/3**); the detector generated **3 alerts for the rapid brute-force scenario** but **0 alerts for the deliberately slow-evasion scenario**.
- **One unexpected result:** The password-spraying scenario produced **0 alerts**, because the current detector groups events by username and does not yet reason about one source attacking multiple accounts.
- **One limitation:** The implementation cannot establish production detection quality because it uses synthetic logs, toy thresholds, and a simplified allowlist for source IPs.
- **Next iteration:** I intend to add source-level and cross-account analysis, then sweep the alert threshold to measure the trade-off between detection and false alarms.
