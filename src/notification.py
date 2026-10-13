from src.contrat import Analyse, Evenement, Notification

def choisir_canal(criticite: str) -> str:
    # CRITICAL et HIGH: TEAMS; MEDIUM: EMAIL; LOW: DASHBOARD; autre valeur: ValueError[cite: 3].
    if criticite in ["CRITICAL", "HIGH"]:
        return "TEAMS"
    elif criticite == "MEDIUM":
        return "EMAIL"
    elif criticite == "LOW":
        return "DASHBOARD"
    else:
        raise ValueError("Criticité non reconnue")

def rediger(evt: Evenement, analyse: Analyse) -> str:
    # Texte de 5 lignes séparées par \n[cite: 3].
    sources_str = ", ".join(analyse.sources)
    return (f"[{analyse.criticite}] Service : {evt.component}\n"
            f"Incident : {evt.message}\n"
            f"Cause probable : {analyse.cause_probable}\n"
            f"Action : {analyse.action_recommandee}\n"
            f"Sources : {sources_str}")

def notifier(evt: Evenement, analyse: Analyse, journal: list) -> Notification:
    # Crée la Notification (canal choisi, destinataire equipe-ops, message rédigé)[cite: 3].
    canal = choisir_canal(analyse.criticite)
    message = rediger(evt, analyse)
    notif = Notification(event_id=evt.id, canal=canal, destinataire="equipe-ops", message=message)
    
    # L'ajoute à la liste journal (historiser)[cite: 3].
    journal.append(notif)
    
    # Passe evt.status à NOTIFIED et la renvoie[cite: 3].
    evt.status = "NOTIFIED"
    return notif

def demander_validation(analyse: Analyse, reponse: str) -> bool:
    # Human-in-the-loop: si l'action n'est pas sensible, True[cite: 3].
    if not analyse.sensible:
        return True
        
    # Sinon True seulement si reponse (sans espaces, sans tenir compte de la casse) vaut o, oui, y ou yes[cite: 3].
    reponse_nettoyee = reponse.strip().lower()
    return reponse_nettoyee in ["o", "oui", "y", "yes"]