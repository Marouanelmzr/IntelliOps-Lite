import unittest

from src.extraction import masquer_secrets, normaliser_docker, normaliser_trivy


LIGNE = "2026-10-05 10:02:11 ERROR backend OOMKilled restarts=14 node=db-02"


class TestExtraction(unittest.TestCase):

    def test_masquer_secrets(self):
        self.assertEqual(
            masquer_secrets("login ok password=abc123 user=bob"),
            "login ok password=[SECRET] user=bob"
        )

    def test_normaliser_docker(self):
        evt = normaliser_docker(LIGNE, 125)

        self.assertEqual(evt.id, "EVT-00125")
        self.assertEqual(evt.timestamp, "2026-10-05T10:02:11Z")
        self.assertEqual(evt.severity, "HIGH")

    def test_normaliser_trivy(self):
        rapport = {
            "Target": "backend",
            "VulnerabilityID": "CVE-2026-1234",
            "PkgName": "lib",
            "InstalledVersion": "1.2.3",
            "Severity": "CRITICAL",
            "Timestamp": "2026-10-05T10:07:00Z",
        }

        evt = normaliser_trivy(rapport, 126)

        self.assertEqual(evt.id, "EVT-00126")
        self.assertEqual(evt.source, "TRIVY")
        self.assertEqual(evt.severity, "CRITICAL")


    


if __name__ == "__main__":
    unittest.main()