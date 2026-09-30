import unittest
from src.generate_scenarios import make_events
from src.detector import detect

class DetectorTests(unittest.TestCase):
    def test_normal_events_do_not_alert(self):
        self.assertEqual(detect([{"timestamp": t.isoformat(), "ip": ip, "username": u, "status": s, "scenario": sc} for t, ip, u, s, sc in make_events("normal")]), [])

    def test_bruteforce_alerts(self):
        rows = [{"timestamp": t.isoformat(), "ip": ip, "username": u, "status": s, "scenario": sc} for t, ip, u, s, sc in make_events("bruteforce")]
        self.assertTrue(detect(rows))

    def test_slow_evasion_is_a_documented_miss(self):
        rows = [{"timestamp": t.isoformat(), "ip": ip, "username": u, "status": s, "scenario": sc} for t, ip, u, s, sc in make_events("slow_evasion")]
        self.assertEqual(detect(rows), [])

if __name__ == "__main__": unittest.main()
