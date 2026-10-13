import unittest
from src.contrat import Analyse, Evenement
from src.notification import choisir_canal, demander_validation, notifier, rediger

def exemple(sensible=True, criticite="CRITICAL"):
    # Base fournie pour initialiser un événement et une analyse[cite: 8].
    e = Evenement("EVT-00125", "2026-10-05T10:02:11Z", "DOCKER", "backend",
                  "production", "CONTAINER_RESTART", "HIGH",
                  "OOMKilled restarts=14")
    a = Analyse("EVT-00125", criticite, "Limite mémoire", "Redémarrer backend",
                sensible, ["DOCKER"])
    return e, a

class TestNotification(unittest.TestCase):
    def test_canaux(self):
        # Vérification des règles de base[cite: 8].
        self.assertEqual(choisir_canal("CRITICAL"), "TEAMS")
        self.assertEqual(choisir_canal("LOW"), "DASHBOARD")
        # Vérification des autres règles[cite: 3].
        self.assertEqual(choisir_canal("HIGH"), "TEAMS")
        self.assertEqual(choisir_canal("MEDIUM"), "EMAIL")
        # Vérification du cas d'erreur[cite: 3].
        with self.assertRaises(ValueError):
            choisir_canal("INCONNU")

    def test_validation(self):
        # Test sur un cas sensible[cite: 8].
        a = exemple()[1]
        self.assertTrue(demander_validation(a, " OUI "))
        self.assertFalse(demander_validation(a, "n"))
        # Tests des autres acceptations valides[cite: 3].
        self.assertTrue(demander_validation(a, "o"))
        self.assertTrue(demander_validation(a, "yes"))
        
        # Test sur un cas non sensible[cite: 3].
        a_non_sensible = exemple(sensible=False)[1]
        self.assertTrue(demander_validation(a_non_sensible, "n"))

    def test_rediger(self):
        # Test de la fonction rediger[cite: 8].
        e, a = exemple()
        message_attendu = (
            "[CRITICAL] Service : backend\n"
            "Incident : OOMKilled restarts=14\n"
            "Cause probable : Limite mémoire\n"
            "Action : Redémarrer backend\n"
            "Sources : DOCKER"
        )
        self.assertEqual(rediger(e, a), message_attendu)

    def test_notifier(self):
        # Test de la fonction notifier[cite: 8].
        e, a = exemple()
        journal = []
        notif = notifier(e, a, journal)
        
        # Vérifications de l'objet Notification et du destinataire equipe-ops[cite: 3].
        self.assertEqual(notif.canal, "TEAMS")
        self.assertEqual(notif.destinataire, "equipe-ops")
        
        # Vérification de l'historisation et du changement de statut[cite: 3].
        self.assertEqual(len(journal), 1)
        self.assertEqual(journal[0], notif)
        self.assertEqual(e.status, "NOTIFIED")

if __name__ == "__main__":
    unittest.main()