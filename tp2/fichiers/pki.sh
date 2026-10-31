#!/usr/bin/env bash

set -euo pipefail

echo "======================================"
echo "   Création de l'infrastructure PKI"
echo "======================================"

# Vérifier que les répertoires existent
mkdir -p racine inter

# ======================================
# 1. Autorité de certification racine
# ======================================

echo "[1/5] Création de l'AC racine..."

openssl genpkey \
    -algorithm EC \
    -pkeyopt ec_paramgen_curve:P-384 \
    -out racine/racine.key

openssl req -x509 -new \
    -key racine/racine.key \
    -sha384 \
    -days 3650 \
    -subj "/C=BF/O=Universite TP/CN=Racine TP" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:1" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -addext "subjectKeyIdentifier=hash" \
    -out racine/racine.crt

openssl x509 -in racine/racine.crt -noout -text

# ======================================
# 2. Autorité de certification intermédiaire
# ======================================

echo "[2/5] Création de l'AC intermédiaire..."

openssl genpkey \
    -algorithm EC \
    -pkeyopt ec_paramgen_curve:P-384 \
    -out inter/inter.key

openssl req -new \
    -key inter/inter.key \
    -sha384 \
    -subj "/C=BF/O=Universite TP/CN=AC Intermediaire TP" \
    -out inter/inter.csr

openssl ca -batch \
    -config racine.cnf \
    -extensions ext_inter \
    -days 1825 \
    -in inter/inter.csr \
    -out inter/inter.crt

# ======================================
# 3. Certificat du serveur HTTPS
# ======================================

echo "[3/5] Création du certificat serveur..."

openssl genpkey \
    -algorithm EC \
    -pkeyopt ec_paramgen_curve:P-256 \
    -out serveur.key

openssl req -new \
    -key serveur.key \
    -subj "/CN=www.tp.local" \
    -addext "subjectAltName=DNS:www.tp.local,DNS:tp.local" \
    -out serveur.csr

openssl ca -batch \
    -config inter.cnf \
    -extensions ext_serveur \
    -days 90 \
    -in serveur.csr \
    -out serveur.crt

# ======================================
# 4. Certificat du client Alice
# ======================================

echo "[4/5] Création du certificat client Alice..."

openssl genpkey \
    -algorithm EC \
    -pkeyopt ec_paramgen_curve:P-256 \
    -out alice.key

openssl req -new \
    -key alice.key \
    -subj "/CN=alice@tp.local" \
    -addext "subjectAltName=email:alice@tp.local" \
    -out alice.csr

openssl ca -batch \
    -config inter.cnf \
    -extensions ext_client \
    -days 90 \
    -in alice.csr \
    -out alice.crt

# ======================================
# 5. Fin du script
# ======================================

echo "[5/5] Vérification des certificats..."

openssl verify \
    -CAfile racine/racine.crt \
    -untrusted inter/inter.crt \
    -purpose sslserver \
    -verify_hostname www.tp.local \
    serveur.crt

openssl verify \
    -CAfile racine/racine.crt \
    -untrusted inter/inter.crt \
    -purpose sslclient \
    alice.crt

echo "======================================"
echo "PKI créée avec succès !"
echo "======================================"
