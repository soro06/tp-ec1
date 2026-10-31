#!/usr/bin/env python3

import argparse
import math
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

# Seuils de surveillance, en jours
SEUIL_ALERTE = 30
SEUIL_CRITIQUE = 7

# Extensions des certificats à surveiller
EXTENSIONS = {".crt", ".pem", ".cer"}


def lire_date_expiration(fichier):
    """Lit la date d'expiration d'un certificat avec OpenSSL."""

    resultat = subprocess.run(
        [
            "openssl", "x509",
            "-in", str(fichier),
            "-noout", "-enddate"
        ],
        capture_output=True,
        text=True
    )

    if resultat.returncode != 0:
        raise ValueError(
            resultat.stderr.strip() or "Certificat illisible"
        )

    # Exemple : notAfter=Oct 31 12:00:00 2026 GMT
    ligne = resultat.stdout.strip()

    if not ligne.startswith("notAfter="):
        raise ValueError("Date d'expiration introuvable")

    date_texte = ligne.split("=", 1)[1]

    date_expiration = datetime.strptime(
        date_texte, "%b %d %H:%M:%S %Y %Z"
    ).replace(tzinfo=timezone.utc)

    return date_expiration


def surveiller_certificat(fichier):
    """Affiche l'état et retourne le code associé."""

    try:
        expiration = lire_date_expiration(fichier)
    except (ValueError, OSError) as erreur:
        print(f"[ERREUR] {fichier} : {erreur}")
        return 2

    maintenant = datetime.now(timezone.utc)
    secondes_restantes = (expiration - maintenant).total_seconds()

    # Nombre de jours arrondi vers le haut pour les certificats valides.
    jours_restants = math.ceil(secondes_restantes / 86400)

    if secondes_restantes <= 0:
        etat = "CRITIQUE"
        code = 2
        message = f"expiré depuis {math.ceil(-secondes_restantes / 86400)} jour(s)"
    elif jours_restants < SEUIL_CRITIQUE:
        etat = "CRITIQUE"
        code = 2
        message = f"{jours_restants} jour(s) restant(s)"
    elif jours_restants < SEUIL_ALERTE:
        etat = "ALERTE"
        code = 1
        message = f"{jours_restants} jour(s) restant(s)"
    else:
        etat = "OK"
        code = 0
        message = f"{jours_restants} jour(s) restant(s)"

    print(f"[{etat}] {fichier} : {message}")
    return code


def main():
    parser = argparse.ArgumentParser(
        description="Surveille les dates d'expiration des certificats X.509."
    )
    parser.add_argument(
        "dossier",
        nargs="?",
        default=".",
        help="Dossier contenant les certificats (par défaut : dossier courant)"
    )
    args = parser.parse_args()

    dossier = Path(args.dossier)

    if not dossier.is_dir():
        print(f"[ERREUR] Dossier introuvable : {dossier}")
        return 2

    fichiers = sorted(
        fichier for fichier in dossier.iterdir()
        if fichier.is_file() and fichier.suffix.lower() in EXTENSIONS
    )

    if not fichiers:
        print(f"[ERREUR] Aucun certificat trouvé dans {dossier}")
        return 2

    code_global = 0

    for fichier in fichiers:
        code = surveiller_certificat(fichier)
        code_global = max(code_global, code)

    print(f"\nCode de sortie global : {code_global}")
    return code_global


if __name__ == "__main__":
    sys.exit(main())
