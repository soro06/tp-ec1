import os
import time
import statistics

from argon2.low_level import hash_secret_raw, Type

MOT_DE_PASSE = b"mot-de-passe-de-test"
SEL = os.urandom(16)
P = 4

# Configurations à tester : (T, M en Kio)
CONFIGURATIONS = [
    (3, 65536),
    (3, 131072),
    (3, 196608),
    (3, 262144),
    (3, 294912),
]

OBJECTIF = 0.5
REPETITIONS = 5

for T, M in CONFIGURATIONS:
    durees = []

    try:
        for _ in range(REPETITIONS):
            debut = time.perf_counter()

            hash_secret_raw(
                secret=MOT_DE_PASSE,
                salt=SEL,
                time_cost=T,
                memory_cost=M,
                parallelism=P,
                hash_len=32,
                type=Type.ID,
            )

            durees.append(time.perf_counter() - debut)

        mediane = statistics.median(durees)

        print(
            f"T={T}, M={M} Kio ({M / 1024:.0f} Mio) : "
            f"{mediane:.3f} s"
        )

    except (MemoryError, OSError) as erreur:
        print(f"T={T}, M={M} Kio : erreur de mémoire ({erreur})")

print(f"\nObjectif : environ {OBJECTIF:.1f} seconde.")