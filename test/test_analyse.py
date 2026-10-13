import unittest

from src.analyse import analyser, classer, est_doublon, rechercher_runbook
from src.contrat import RUNBOOKS, Analyse, Evenement


def evt(event_type="LOG", severity="LOW", message="ok",
        component="backend", source="DOCKER"):
    return Evenement(
        id="EVT-00001",
        timestamp="2026-10-05T10:00:00Z",
        source=source,
        component=component,
        environment="production",
        event_type=event_type,
        severity=severity,
        message=message,
    )


class TestAnalyse(unittest.TestCase):

    def test_doublon(self):
        vus = set()
        self.assertFalse(est_doublon(evt(message="a"), vus))
        self.assertTrue(est_doublon(evt(message="a"), vus))
        self.assertEqual(len(vus), 1)

    def test_cle_doublon(self):
        vus = set()
        est_doublon(evt(), vus)

        for modification in (
            {"source": "TRIVY"},
            {"component": "frontend"},
            {"event_type": "VULNERABILITY"},
            {"message": "autre message"},
        ):
            with self.subTest(modification=modification):
                self.assertFalse(est_doublon(evt(**modification), vus))

    def test_runbook_insensible_casse(self):
        e = evt(message="Erreur oomkilled")
        self.assertEqual(
            rechercher_runbook(e, RUNBOOKS),
            RUNBOOKS["OOMKilled"],
        )

    def test_runbook_premier_mot_cle_de_la_base(self):
        base = {"timeout": "Procédure réseau", "CVE": "Procédure sécurité"}
        e = evt(message="CVE détectée après un timeout")
        self.assertEqual(rechercher_runbook(e, base), "Procédure réseau")

    def test_runbook_absent(self):
        self.assertIsNone(rechercher_runbook(evt(), RUNBOOKS))

    def test_classer_redemarrages(self):
        e = evt("CONTAINER_RESTART", "HIGH", "OOMKilled restarts=14")
        self.assertEqual(classer(e), "CRITICAL")

    def test_classer_seuil_dix(self):
        e = evt("CONTAINER_RESTART", "HIGH", "restarts=10")
        self.assertEqual(classer(e), "CRITICAL")

    def test_classer_redemarrages_inferieurs_dix(self):
        e = evt("CONTAINER_RESTART", "HIGH", "restarts=9")
        self.assertEqual(classer(e), "MEDIUM")

    def test_classer_vulnerabilite_critique(self):
        e = evt("VULNERABILITY", "CRITICAL", "CVE détectée")
        self.assertEqual(classer(e), "HIGH")

    def test_classer_autres_evenements(self):
        for type_evenement in ("LOG", "VULNERABILITY"):
            for severite in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
                if type_evenement == "VULNERABILITY" and severite == "CRITICAL":
                    continue
                with self.subTest(type=type_evenement, severity=severite):
                    self.assertEqual(
                        classer(evt(type_evenement, severite)),
                        severite,
                    )

    def test_analyser_redemarrage(self):
        e = evt("CONTAINER_RESTART", "HIGH", "OOMKilled restarts=14")
        resultat = analyser(e, RUNBOOKS)

        self.assertIsInstance(resultat, Analyse)
        self.assertEqual(resultat.event_id, e.id)
        self.assertEqual(resultat.criticite, "CRITICAL")
        self.assertEqual(resultat.cause_probable, RUNBOOKS["OOMKilled"])
        self.assertEqual(resultat.action_recommandee, "Redémarrer backend")
        self.assertTrue(resultat.sensible)
        self.assertEqual(resultat.sources, ["DOCKER"])
        self.assertEqual(e.status, "ANALYSED")

    def test_analyser_vulnerabilite(self):
        e = evt(
            "VULNERABILITY", "CRITICAL",
            "CVE détectée", source="TRIVY",
        )
        resultat = analyser(e, RUNBOOKS)

        self.assertEqual(resultat.criticite, "HIGH")
        self.assertEqual(resultat.cause_probable, RUNBOOKS["CVE"])
        self.assertEqual(
            resultat.action_recommandee,
            "Mettre à jour la dépendance",
        )
        self.assertTrue(resultat.sensible)
        self.assertEqual(resultat.sources, ["TRIVY"])
        self.assertEqual(e.status, "ANALYSED")

    def test_analyser_sans_runbook(self):
        e = evt()
        resultat = analyser(e, RUNBOOKS)

        self.assertEqual(
            resultat.cause_probable,
            "Cause inconnue : analyse manuelle requise",
        )
        self.assertEqual(resultat.action_recommandee, "Consulter les logs")
        self.assertEqual(e.status, "ANALYSED")

    def test_action_sensible_selon_criticite(self):
        for criticite in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
            with self.subTest(criticite=criticite):
                resultat = analyser(evt(severity=criticite), RUNBOOKS)
                self.assertEqual(
                    resultat.sensible,
                    criticite in ("HIGH", "CRITICAL"),
                )


if __name__ == "__main__":
    unittest.main()