import re

from src.contrat import Analyse, Evenement


def est_doublon(evt: Evenement, deja_vus: set) -> bool:
    cle = (
        evt.source,
        evt.component,
        evt.event_type,
        evt.message,
    )

    if cle in deja_vus:
        return True

    deja_vus.add(cle)
    return False


def rechercher_runbook(evt: Evenement, base: dict):
    message = evt.message.lower()

    for mot_cle, procedure in base.items():
        if mot_cle.lower() in message:
            return procedure

    return None


def classer(evt: Evenement) -> str:
    if evt.event_type == "CONTAINER_RESTART":
        resultat = re.search(r"restarts=(\d+)", evt.message)
        redemarrages = int(resultat.group(1)) if resultat else 0

        if redemarrages >= 10:
            return "CRITICAL"

        return "MEDIUM"

    if evt.event_type == "VULNERABILITY" and evt.severity == "CRITICAL":
        return "HIGH"

    return evt.severity


def analyser(evt: Evenement, base: dict) -> Analyse:
    criticite = classer(evt)
    procedure = rechercher_runbook(evt, base)

    cause_probable = (
        procedure
        if procedure is not None
        else "Cause inconnue : analyse manuelle requise"
    )

    if evt.event_type == "CONTAINER_RESTART":
        action = f"Redémarrer {evt.component}"
    elif evt.event_type == "VULNERABILITY":
        action = "Mettre à jour la dépendance"
    else:
        action = "Consulter les logs"

    analyse = Analyse(
        event_id=evt.id,
        criticite=criticite,
        cause_probable=cause_probable,
        action_recommandee=action,
        sensible=criticite in ("HIGH", "CRITICAL"),
        sources=[evt.source],
    )

    evt.status = "ANALYSED"

    return analyse