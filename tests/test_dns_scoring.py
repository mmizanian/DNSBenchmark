import unittest

from DNSB import compute_dns_score, iter_scan_batches


class DNSScoringTests(unittest.TestCase):
    def test_compute_dns_score_is_numeric_and_rewards_fast_success(self) -> None:
        score = compute_dns_score(success_rate=100.0, avg_ms=20.0, std_dev_ms=5.0)
        self.assertGreaterEqual(score, 80.0)
        self.assertLessEqual(score, 100.0)

    def test_compute_dns_score_penalizes_hijacked_servers(self) -> None:
        score = compute_dns_score(success_rate=100.0, avg_ms=10.0, std_dev_ms=1.0, hijacked=True)
        self.assertLess(score, -9000.0)

    def test_iter_scan_batches_splits_large_host_lists(self) -> None:
        hosts = [str(i) for i in range(600)]
        batches = list(iter_scan_batches(hosts, batch_size=512))
        self.assertEqual(len(batches), 2)
        self.assertEqual(len(batches[0]), 512)
        self.assertEqual(len(batches[1]), 88)


if __name__ == "__main__":
    unittest.main()
