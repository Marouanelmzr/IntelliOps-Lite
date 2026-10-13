
import re
from datetime import datetime, timezone

from src.contrat import Evenement, SEVERITES


def masquer_secrets(texte: str) -> str:
    """Masque les mots de passe et autres secrets dans un texte."""
    motif = r'\b(password|passwd|pwd|token|api_key|apikey|secret)\s*=\s*("[^"]*"|\'[^\']*\'|[^\s]+)'

    return re.sub(
        motif,
        lambda m: f"{m.group(1)}=[SECRET]",
        texte,
        flags=re.IGNORECASE
    )


def normaliser_docker(
    ligne: str,
    numero: int,
    environment: str = "production"
) -> Evenement:
    """Transforme une ligne de log Docker en événement normalisé."""

    motif = (
        r'^(\d{4}-\d{2}-\d{2}) '
        r'(\d{2}:\d{2}:\d{2}) '
        r'(ERROR|WARN|WARNING|INFO|DEBUG) '
        r'(\S+) (.*)$'
    )

    match = re.match(motif, ligne.strip(), re.IGNORECASE)

    if not match:
        raise ValueError("Format de log Docker invalide")

    date, heure, niveau, component, message = match.groups()

    timestamp = datetime.strptime(
        f"{date} {heure}", "%Y-%m-%d %H:%M:%S"
    ).replace(tzinfo=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    niveau = niveau.upper()

    correspondance = {
        "ERROR": "HIGH",
        "WARN": "MEDIUM",
        "WARNING": "MEDIUM",
        "INFO": "LOW",
        "DEBUG": "LOW",
    }

    severity = correspondance[niveau]

    # Utilise uniquement les sévérités autorisées par le contrat.
    if severity not in SEVERITES:
        raise ValueError(f"Sévérité non autorisée : {severity}")

    message = masquer_secrets(message)

    event_type = (
        "CONTAINER_RESTART"
        if "restarts=" in message.lower()
        else "LOG"
    )

    return Evenement(
        f"EVT-{numero:05d}",
        timestamp,
        "DOCKER",
        component,
        environment,
        event_type,
        severity,
        message
    )


def normaliser_trivy(
    rapport: dict,
    numero: int,
    environment: str = "production"
) -> Evenement:
    """Transforme un rapport de vulnérabilité Trivy en événement."""

    timestamp_brut = rapport.get("Timestamp")

    if not timestamp_brut:
        timestamp = datetime.now(timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
    else:
        try:
            dt = datetime.fromisoformat(
                timestamp_brut.replace("Z", "+00:00")
            )
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            timestamp = dt.astimezone(timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            )
        except (ValueError, TypeError):
            raise ValueError("Timestamp Trivy invalide")

    severite_trivy = str(
        rapport.get("Severity", "UNKNOWN")
    ).upper()

    correspondance = {
        "CRITICAL": "CRITICAL",
        "HIGH": "HIGH",
        "MEDIUM": "MEDIUM",
        "LOW": "LOW",
        "UNKNOWN": "LOW",
    }

    severity = correspondance.get(severite_trivy, "LOW")

    if severity not in SEVERITES:
        raise ValueError(f"Sévérité non autorisée : {severity}")

    component = str(rapport.get("Target", "unknown"))

    message = (
        f"Vulnérabilité {rapport.get('VulnerabilityID', 'inconnue')} "
        f"dans {rapport.get('PkgName', 'paquet inconnu')} "
        f"(version {rapport.get('InstalledVersion', 'inconnue')})"
    )

    message = masquer_secrets(message)

    return Evenement(
        f"EVT-{numero:05d}",
        timestamp,
        "TRIVY",
        component,
        environment,
        "VULNERABILITY",
        severity,
        message
    )
