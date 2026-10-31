import struct

import pytest
from cryptography.exceptions import InvalidTag

from coffre import (
    chiffrer,
    dechiffrer,
    MAGIC,
    T,
    M,
    P,
)


# --------------------------------------------------
# 1. Test aller-retour
# --------------------------------------------------

def test_aller_retour():
    b = chiffrer("correct horse", "notes.txt", b"secret")

    assert dechiffrer("correct horse", "notes.txt", b) == b"secret"


# --------------------------------------------------
# 2. Deux chiffrements différents
# --------------------------------------------------

def test_deux_chiffrements_differents():
    b1 = chiffrer("pw", "a", b"x")
    b2 = chiffrer("pw", "a", b"x")

    assert b1 != b2


# --------------------------------------------------
# 3. Mauvais mot de passe
# --------------------------------------------------

def test_mauvais_mot_de_passe():
    b = chiffrer("pw", "a", b"x")

    with pytest.raises(InvalidTag):
        dechiffrer("autre", "a", b)


# --------------------------------------------------
# 4. Modification d'un octet du contenu chiffré
# --------------------------------------------------

def test_octet_modifie():
    b = bytearray(chiffrer("pw", "a", b"x" * 100))

    b[-20] ^= 1

    with pytest.raises(InvalidTag):
        dechiffrer("pw", "a", bytes(b))


# --------------------------------------------------
# 5. Changement du nom du fichier
# --------------------------------------------------

def test_nom_echange():
    b = chiffrer("pw", "salaires.xlsx", b"x")

    with pytest.raises(InvalidTag):
        dechiffrer("pw", "menu.txt", b)


# --------------------------------------------------
# 6. Vérification de l'identifiant du format
# --------------------------------------------------

def test_identifiant_format():
    b = chiffrer("pw", "a", b"x")

    assert b[:4] == MAGIC
    assert MAGIC == b"CFR1"


# --------------------------------------------------
# 7. Vérification de la taille de l'en-tête
# --------------------------------------------------

def test_taille_entete():
    b = chiffrer("pw", "a", b"x")

    # En-tête de 44 octets et étiquette GCM de 16 octets.
    assert len(b) == 44 + len(b"x") + 16


# --------------------------------------------------
# 8. Vérification des paramètres Argon2id
# --------------------------------------------------

def test_parametres_argon2id():
    b = chiffrer("pw", "a", b"x")

    t, m, p = struct.unpack(">III", b[4:16])

    assert (t, m, p) == (T, M, P)


# --------------------------------------------------
# 9. Rejet d'un format inconnu
# --------------------------------------------------

def test_format_inconnu():
    b = bytearray(chiffrer("pw", "a", b"x"))

    b[0:4] = b"XXXX"

    with pytest.raises(ValueError, match="Format inconnu"):
        dechiffrer("pw", "a", bytes(b))


# --------------------------------------------------
# 10. Rejet d'un fichier trop court
# --------------------------------------------------

def test_fichier_trop_court():
    with pytest.raises(ValueError):
        dechiffrer("pw", "a", b"CFR1")


# --------------------------------------------------
# 11. Vérification des données vides
# --------------------------------------------------

def test_donnees_vides():
    b = chiffrer("pw", "vide.txt", b"")

    assert dechiffrer("pw", "vide.txt", b) == b""


# --------------------------------------------------
# 12. Modification du nonce
# --------------------------------------------------

def test_nonce_modifie():
    b = bytearray(chiffrer("pw", "a", b"donnees confidentielles"))

    # Le nonce occupe les octets 32 à 43.
    b[32] ^= 1

    with pytest.raises(InvalidTag):
        dechiffrer("pw", "a", bytes(b))