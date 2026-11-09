#!/usr/bin/env python3
"""Generate known-answer vectors from the independent pure-Python ML-KEM
implementation `kyber-py` (pip install kyber-py).

Each line of tests/kat/<level>.kat:
    seed(d||z, 64B hex) m(32B hex) SHA3-256(ek) SHA3-256(dk) SHA3-256(ct) K(hex)
"""
import hashlib
import os

from kyber_py.ml_kem import ML_KEM_512, ML_KEM_768, ML_KEM_1024

COUNT = 20
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "kat")
os.makedirs(OUT, exist_ok=True)


def h(b):
    return hashlib.sha3_256(b).hexdigest()


def stream(label, i, n):
    return hashlib.shake_256(f"{label}-{i}".encode()).digest(n)


for name, kem in (("mlkem512", ML_KEM_512), ("mlkem768", ML_KEM_768),
                  ("mlkem1024", ML_KEM_1024)):
    lines = []
    for i in range(COUNT):
        seed = stream(name + "-seed", i, 64)
        m = stream(name + "-msg", i, 32)
        ek, dk = kem.key_derive(seed)
        K, c = kem._encaps_internal(ek, m)
        assert kem.decaps(dk, c) == K
        lines.append(" ".join([seed.hex(), m.hex(), h(ek), h(dk), h(c), K.hex()]))
    with open(os.path.join(OUT, name + ".kat"), "w") as f:
        f.write("\n".join(lines) + "\n")
    print(name, "wrote", COUNT, "vectors")
