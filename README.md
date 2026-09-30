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
