#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

# Répertoire principal de la PKI
PKI_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$PKI_DIR"

# Fichiers de l'autorité intermédiaire et de la racine
INTER_CONFIG="$PKI_DIR/inter.cnf"
INTER_CERT="$PKI_DIR/inter/inter.crt"
ROOT_CERT="$PKI_DIR/racine/racine.crt"

# Configuration Nginx
TLS_DIR="/etc/nginx/tls"
SERVER_KEY="$TLS_DIR/serveur.key"
SERVER_CHAIN="$TLS_DIR/serveur_chaine.crt"

SERVER_NAME="www.tp.local"
VALIDITY_DAYS=90
RENEW_BEFORE_DAYS=30

# Vérifications initiales
for fichier in "$INTER_CONFIG" "$INTER_CERT" "$ROOT_CERT" \
               "$SERVER_KEY" "$SERVER_CHAIN"; do
    if [[ ! -r "$fichier" ]]; then
        echo "[ERREUR] Fichier absent ou illisible : $fichier" >&2
        exit 2
    fi
done

# Éviter deux renouvellements simultanés
exec 9>"$PKI_DIR/.renouveler.lock"
if ! flock -n 9; then
    echo "[INFO] Un renouvellement est déjà en cours."
    exit 0
fi

# Vérifier si le certificat actuel expire dans moins de 30 jours.
# Si OpenSSL confirme qu'il reste au moins 30 jours, aucune action n'est nécessaire.
if openssl x509 -in "$SERVER_CHAIN" \
        -noout -checkend "$((RENEW_BEFORE_DAYS * 86400))" \
        >/dev/null 2>&1; then
    echo "[OK] Le certificat expire dans au moins ${RENEW_BEFORE_DAYS} jours. Aucun renouvellement nécessaire."
    exit 0
fi

echo "[INFO] Le certificat expire dans moins de ${RENEW_BEFORE_DAYS} jours."
echo "[INFO] Préparation du renouvellement de $SERVER_NAME..."

# Le déploiement dans /etc/nginx nécessite les privilèges root.
if [[ "$EUID" -ne 0 ]]; then
    echo "[ERREUR] Exécuter ce script avec sudo ou en tant que root." >&2
    exit 2
fi

# Vérifier la présence des commandes nécessaires
for commande in openssl nginx install flock; do
    if ! command -v "$commande" >/dev/null 2>&1; then
        echo "[ERREUR] Commande introuvable : $commande" >&2
        exit 2
    fi
done

# Préparer un espace de travail temporaire protégé
TMP_DIR="$(mktemp -d "$PKI_DIR/.renouveler.XXXXXXXX")"
BACKUP_DIR="$TLS_DIR/sauvegardes/$(date +%Y%m%d_%H%M%S)"

DEPLOY_STARTED=0
DEPLOY_COMPLETE=0

# Restaurer les anciens fichiers si le déploiement échoue.
rollback() {
    local code=$?
    trap - ERR

    if [[ "$DEPLOY_STARTED" -eq 1 && "$DEPLOY_COMPLETE" -eq 0 ]]; then
        echo "[ERREUR] Échec du déploiement. Tentative de restauration..." >&2

        if [[ -d "$BACKUP_DIR" ]]; then
            install -o root -g root -m 600 \
                "$BACKUP_DIR/serveur.key" "$SERVER_KEY"
            install -o root -g root -m 644 \
                "$BACKUP_DIR/serveur_chaine.crt" "$SERVER_CHAIN"

            if nginx -t; then
                if nginx -s reload; then
                    echo "[INFO] Ancienne configuration restaurée." >&2
                else
                    echo "[ERREUR] La restauration a échoué lors du rechargement de Nginx." >&2
                fi
            else
                echo "[ERREUR] La configuration restaurée ne passe pas nginx -t." >&2
            fi
        fi
    fi

    rm -rf -- "$TMP_DIR"
    exit "$code"
}
trap rollback ERR

# 1. Générer une nouvelle clé privée EC P-256
openssl genpkey \
    -algorithm EC \
    -pkeyopt ec_paramgen_curve:P-256 \
    -out "$TMP_DIR/serveur.key"

chmod 600 "$TMP_DIR/serveur.key"

# 2. Générer la demande de signature (CSR) avec le nom DNS du serveur
openssl req -new \
    -key "$TMP_DIR/serveur.key" \
    -subj "/CN=$SERVER_NAME" \
    -addext "subjectAltName=DNS:$SERVER_NAME,DNS:tp.local" \
    -out "$TMP_DIR/serveur.csr"

# 3. Faire signer la demande par l'autorité intermédiaire
openssl ca -batch \
    -config "$INTER_CONFIG" \
    -extensions ext_serveur \
    -days "$VALIDITY_DAYS" \
    -in "$TMP_DIR/serveur.csr" \
    -out "$TMP_DIR/serveur.crt"

# Vérifier que le certificat correspond à la nouvelle clé privée
openssl x509 -in "$TMP_DIR/serveur.crt" -pubkey -noout \
    | openssl pkey -pubin -outform DER \
    > "$TMP_DIR/cert_public.der"

openssl pkey -in "$TMP_DIR/serveur.key" -pubout -outform DER \
    > "$TMP_DIR/key_public.der"

if ! cmp -s "$TMP_DIR/cert_public.der" "$TMP_DIR/key_public.der"; then
    echo "[ERREUR] Le certificat ne correspond pas à la clé privée." >&2
    exit 1
fi

# 4. Vérifier la chaîne jusqu'à la racine AVANT tout déploiement
openssl verify \
    -purpose sslserver \
    -verify_hostname "$SERVER_NAME" \
    -CAfile "$ROOT_CERT" \
    -untrusted "$INTER_CERT" \
    "$TMP_DIR/serveur.crt"

# Préparer le fichier de chaîne : certificat serveur puis intermédiaire
cat "$TMP_DIR/serveur.crt" "$INTER_CERT" \
    > "$TMP_DIR/serveur_chaine.crt"

# 5. Vérifier également que Nginx pourra lire la nouvelle configuration
# La clé et le certificat ne sont pas encore installés à ce stade.
echo "[INFO] Chaîne vérifiée. Préparation du déploiement..."

# Sauvegarder les fichiers actuellement utilisés avant de les remplacer
mkdir -p "$BACKUP_DIR"
chmod 700 "$BACKUP_DIR"

install -o root -g root -m 600 \
    "$SERVER_KEY" "$BACKUP_DIR/serveur.key"
install -o root -g root -m 644 \
    "$SERVER_CHAIN" "$BACKUP_DIR/serveur_chaine.crt"

echo "[INFO] Sauvegarde créée : $BACKUP_DIR"

# 6. Déployer les nouveaux fichiers
DEPLOY_STARTED=1

install -o root -g root -m 600 \
    "$TMP_DIR/serveur.key" "$SERVER_KEY"
install -o root -g root -m 644 \
    "$TMP_DIR/serveur_chaine.crt" "$SERVER_CHAIN"

# Tester la configuration avant le rechargement
nginx -t

# Recharger Nginx sans arrêter le service
nginx -s reload

DEPLOY_COMPLETE=1

# Archiver aussi le certificat renouvelé pour faciliter l'audit
install -o root -g root -m 644 \
    "$TMP_DIR/serveur.crt" "$BACKUP_DIR/serveur_renouvele.crt"

echo "[SUCCÈS] Certificat renouvelé et déployé pour $SERVER_NAME."
echo "[INFO] Validité demandée : $VALIDITY_DAYS jours."
echo "[INFO] Sauvegarde de l'ancien certificat et de l'ancienne clé : $BACKUP_DIR"

# Nettoyage
rm -rf -- "$TMP_DIR"
trap - ERR
exit 0
