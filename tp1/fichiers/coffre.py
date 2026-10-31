import os
import struct

from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag

MAGIC = b"CFR1"
T, M, P = 3, 64 * 1024, 4

TAILLE_ENTETE = 44
TAILLE_ETIQUETTE = 16


def cle_maitresse(mot_de_passe: str, sel: bytes) -> bytes:
    """Dérive une clé maîtresse de 32 octets avec Argon2id."""
    if not isinstance(mot_de_passe, str) or not mot_de_passe:
        raise ValueError("Le mot de passe doit être une chaîne non vide.")

    if not isinstance(sel, bytes) or len(sel) != 16:
        raise ValueError("Le sel doit contenir exactement 16 octets.")

    return hash_secret_raw(
        secret=mot_de_passe.encode("utf-8"),
        salt=sel,
        time_cost=T,
        memory_cost=M,
        parallelism=P,
        hash_len=32,
        type=Type.ID,
    )


def sous_cle(maitresse: bytes, usage: bytes) -> bytes:
    """Dérive une sous-clé de 32 octets avec HKDF-SHA256."""
    if not isinstance(maitresse, bytes) or len(maitresse) != 32:
        raise ValueError("La clé maîtresse doit contenir 32 octets.")

    if not isinstance(usage, bytes) or not usage:
        raise ValueError("L'usage doit être un objet bytes non vide.")

    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"coffre-v1|" + usage,
    ).derive(maitresse)


def chiffrer(mot_de_passe: str, nom: str, donnees: bytes) -> bytes:
    """
    Chiffre les données et renvoie un blob au format CFR1.

    En-tête :
        4 octets  : MAGIC
        12 octets : paramètres Argon2id (T, M, P)
        16 octets : sel
        12 octets : nonce

    Le contenu chiffré est suivi de l'étiquette d'authentification GCM.
    """
    if not isinstance(nom, str) or not nom:
        raise ValueError("Le nom doit être une chaîne non vide.")

    if not isinstance(donnees, bytes):
        raise TypeError("Les données doivent être de type bytes.")

    # Générer un sel et un nonce nouveaux à chaque appel.
    sel = os.urandom(16)
    nonce = os.urandom(12)

    # Construire l'en-tête.
    entete = MAGIC + struct.pack(">III", T, M, P) + sel + nonce

    # Dériver la clé de chiffrement.
    maitresse = cle_maitresse(mot_de_passe, sel)
    k = sous_cle(maitresse, b"fichiers")

    # Authentifier l'en-tête complet et le nom du fichier.
    ad = entete + nom.encode("utf-8")

    chiffre = AESGCM(k).encrypt(nonce, donnees, ad)

    return entete + chiffre


def dechiffrer(mot_de_passe: str, nom: str, blob: bytes) -> bytes:
    """
    Déchiffre un blob CFR1.

    Refuse les formats inconnus, les en-têtes incomplets et les paramètres
    Argon2id hors des limites autorisées.
    """
    if not isinstance(mot_de_passe, str) or not mot_de_passe:
        raise ValueError("Le mot de passe doit être une chaîne non vide.")

    if not isinstance(nom, str) or not nom:
        raise ValueError("Le nom doit être une chaîne non vide.")

    if not isinstance(blob, bytes):
        raise TypeError("Le blob doit être de type bytes.")

    # Vérifier la taille minimale : en-tête + étiquette GCM.
    if len(blob) < TAILLE_ENTETE + TAILLE_ETIQUETTE:
        raise ValueError("Fichier chiffré trop court.")

    # Vérifier le format.
    entete = blob[:TAILLE_ENTETE]

    if entete[:4] != MAGIC:
        raise ValueError("Format inconnu.")

    # Relire les paramètres Argon2id dans l'en-tête.
    t, m, p = struct.unpack(">III", entete[4:16])

    # Vérifier les paramètres avant de lancer Argon2id.
    if not (1 <= t <= 10):
        raise ValueError("Paramètre T invalide.")

    if not (8192 <= m <= 1024 * 1024):
        raise ValueError("Paramètre M invalide.")

    if not (1 <= p <= 16) or m < 8 * p:
        raise ValueError("Paramètre P invalide.")

    # Extraire le sel, le nonce et le texte chiffré.
    sel = entete[16:32]
    nonce = entete[32:44]
    chiffre = blob[TAILLE_ENTETE:]

    # Reconstituer la clé maîtresse avec les paramètres enregistrés.
    maitresse = hash_secret_raw(
        secret=mot_de_passe.encode("utf-8"),
        salt=sel,
        time_cost=t,
        memory_cost=m,
        parallelism=p,
        hash_len=32,
        type=Type.ID,
    )

    k = sous_cle(maitresse, b"fichiers")

    # Les données associées doivent être identiques à celles du chiffrement.
    ad = entete + nom.encode("utf-8")

    try:
        return AESGCM(k).decrypt(nonce, chiffre, ad)
    except InvalidTag as exc:
        raise ValueError(
            "Déchiffrement impossible : mot de passe incorrect, "
            "nom différent ou fichier modifié."
        ) from exc
        
        

def rechiffrer(
    ancien_mdp: str,
    nouveau_mdp: str,
    nom: str,
    blob: bytes
) -> bytes:
    """
    Change le mot de passe d'un fichier chiffré.

    Le fichier est d'abord déchiffré avec l'ancien mot de passe,
    puis chiffré à nouveau avec le nouveau mot de passe.

    Les paramètres Argon2id actuels sont utilisés pour le nouveau blob.
    L'ancien blob reste inchangé.
    """
    if not isinstance(nouveau_mdp, str) or not nouveau_mdp:
        raise ValueError("Le nouveau mot de passe ne doit pas être vide.")

    # 1. Déchiffrer avec l'ancien mot de passe.
    donnees = dechiffrer(ancien_mdp, nom, blob)

    # 2. Chiffrer avec le nouveau mot de passe.
    nouveau_blob = chiffrer(nouveau_mdp, nom, donnees)

    return nouveau_blob