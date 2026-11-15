"""Generate the HPSP commissioning (SPAKE2+) test vector. Test values only."""
import hashlib, hmac, json, sys, uuid
sys.path.insert(0, __import__('os').path.dirname(__file__))
from spake2plus import run, hkdf, n, G, enc

DEVICE_ID = '7b1c2d3e-4f50-4a61-8b72-93a4b5c6d7e8'
CODE = '7KQ4M9TW'
SALT = hashlib.sha256(b'HPSP example commissioning salt').digest()[:16]
ITER = 100000
CONTEXT = b'HPSP-1 commissioning'
ID_P = b'HPSP-controller'
ID_V = uuid.UUID(DEVICE_ID).bytes

def derive(code, salt, it):
    ws = hashlib.pbkdf2_hmac('sha256', code.encode('ascii'), salt, it, 80)
    return int.from_bytes(ws[:40], 'big') % n, int.from_bytes(ws[40:], 'big') % n

w0, w1 = derive(CODE, SALT, ITER)
x = int.from_bytes(hashlib.sha256(b'HPSP example prover scalar').digest(), 'big') % n
y = int.from_bytes(hashlib.sha256(b'HPSP example verifier scalar').digest(), 'big') % n
r = run(CONTEXT, ID_P, ID_V, w0, w1, x, y)
psk = hkdf(r['K_shared'], b'HPSP-1 commissioning psk', 32) if False else None
# HKDF-Expand only (PRK = K_shared), as the specification states
def hkdf_expand(prk, info, L):
    out = b''; t = b''; i = 1
    while len(out) < L:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest(); out += t; i += 1
    return out[:L]
psk = hkdf_expand(r['K_shared'], b'HPSP-1 commissioning psk', 32)
vec = dict(code=CODE, salt_hex=SALT.hex(), iterations=ITER, context=CONTEXT.decode(), id_prover=ID_P.decode(),
           id_verifier_hex=ID_V.hex(), w0_hex=w0.to_bytes(32, 'big').hex(), w1_hex=w1.to_bytes(32, 'big').hex(),
           L_hex=r['L'].hex(), x_hex=x.to_bytes(32, 'big').hex(), y_hex=y.to_bytes(32, 'big').hex(),
           shareP_hex=r['shareP'].hex(), shareV_hex=r['shareV'].hex(), K_main_hex=r['K_main'].hex(),
           confirmP_hex=r['confirmP'].hex(), confirmV_hex=r['confirmV'].hex(), K_shared_hex=r['K_shared'].hex(), psk_hex=psk.hex())
out = sys.argv[1] if len(sys.argv) > 1 else 'pake_vec.json'
json.dump(vec, open(out, 'w'), indent=1)
print('wrote', out)
