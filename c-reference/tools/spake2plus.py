"""SPAKE2+ (RFC 9383), P256-SHA256-HKDF-SHA256-HMAC-SHA256 - reference for HPSP commissioning.
Not constant time: for test-vector generation only, never for production."""
import hashlib, hmac, struct
from ecdsa import NIST256p
from ecdsa.ellipticcurve import PointJacobi, Point

C = NIST256p.curve; G = NIST256p.generator; n = NIST256p.order; h = 1
def dec(hexs):
    b = bytes.fromhex(hexs); p = C.p()
    x = int.from_bytes(b[1:], 'big'); y2 = (pow(x, 3, p) - 3 * x + C.b()) % p
    y = pow(y2, (p + 1) // 4, p)
    if (y & 1) != (b[0] & 1): y = p - y
    return Point(C, x, y, n)
M = dec('02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f')
N = dec('03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49')
def enc(P): return b'\x04' + P.x().to_bytes(32, 'big') + P.y().to_bytes(32, 'big')
def neg(P): return Point(C, P.x(), (-P.y()) % C.p(), n)
def lp(b): return struct.pack('<Q', len(b)) + b
def hkdf(ikm, info, L=32, salt=b''):
    prk = hmac.new(salt or b'\0' * 32, ikm, hashlib.sha256).digest()
    out = b''; t = b''; i = 1
    while len(out) < L:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest(); out += t; i += 1
    return out[:L]

def run(context, idP, idV, w0, w1, x, y):
    L = w1 * G
    X = x * G + w0 * M            # shareP (prover)
    Y = y * G + w0 * N            # shareV (verifier)
    # verifier side
    Zv = (h * y) * (X + neg(w0 * M)); Vv = (h * y) * L
    # prover side
    T = Y + neg(w0 * N); Zp = (h * x) * T; Vp = (h * w1) * T
    assert enc(Zv) == enc(Zp) and enc(Vv) == enc(Vp)
    TT = b''.join(lp(f) for f in [context, idP, idV, enc(M), enc(N), enc(X), enc(Y), enc(Zp), enc(Vp), w0.to_bytes(32, 'big')])
    Kmain = hashlib.sha256(TT).digest()
    ck = hkdf(Kmain, b'ConfirmationKeys', 64); KcP, KcV = ck[:32], ck[32:]
    Kshared = hkdf(Kmain, b'SharedKey', 32)
    confirmP = hmac.new(KcP, enc(Y), hashlib.sha256).digest()
    confirmV = hmac.new(KcV, enc(X), hashlib.sha256).digest()
    return dict(L=enc(L), shareP=enc(X), shareV=enc(Y), Z=enc(Zp), V=enc(Vp), TT=TT, K_main=Kmain,
                K_confirmP=KcP, K_confirmV=KcV, confirmP=confirmP, confirmV=confirmV, K_shared=Kshared)

def rfc_check():
    r = run(b'SPAKE2+-P256-SHA256-HKDF-SHA256-HMAC-SHA256 Test Vectors', b'client', b'server',
            0xbb8e1bbcf3c48f62c08db243652ae55d3e5586053fca77102994f23ad95491b3,
            0x7e945f34d78785b8a3ef44d0df5a1a97d6b3b460409a345ca7830387a74b1dba,
            0xd1232c8e8693d02368976c174e2088851b8365d0d79a9eee709c6a05a2fad539,
            0x717a72348a182085109c8d3917d6c43d59b224dc6a7fc4f0483232fa6516d8b3)
    exp = dict(K_main='4c59e1ccf2cfb961aa31bd9434478a1089b56cd11542f53d3576fb6c2a438a29',
               K_confirmP='871ae3f7b78445e34438fb284504240239031c39d80ac23eb5ab9be5ad6db58a',
               K_confirmV='ccd53c7c1fa37b64a462b40db8be101cedcf838950162902054e644b400f1680',
               confirmP='926cc713504b9b4d76c9162ded04b5493e89109f6d89462cd33adc46fda27527',
               confirmV='9747bcc4f8fe9f63defee53ac9b07876d907d55047e6ff2def2e7529089d3e68',
               K_shared='0c5f8ccd1413423a54f6c1fb26ff01534a87f893779c6e68666d772bfd91f3e7')
    for k, v in exp.items():
        assert r[k].hex() == v, (k, r[k].hex(), v)
    return True

if __name__ == '__main__':
    print('RFC 9383 vector reproduced:', rfc_check())
