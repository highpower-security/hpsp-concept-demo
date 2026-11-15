"""HPSP controller simulator - drives the reference device through test scenarios.

TEST USE ONLY: plain TCP on localhost, published test signing key.
Usage: python3 tools/sim_controller.py ./hpsp_device
"""
import json, os, socket, struct, subprocess, sys, time
from datetime import datetime, timezone
import cbor2
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
V = json.load(open(os.path.join(ROOT, 'vectors/spec_vectors.json')))
KEY = ec.derive_private_key(int(V['privHex'], 16), ec.SECP256R1())
SIGNER = bytes.fromhex(V['signerHex'])
UUID = bytes.fromhex(V['uuidHex'])
N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551

results = []
def check(cond, what):
    results.append((bool(cond), what))
    print(('PASS ' if cond else 'FAIL ') + what, flush=True)

def sign_grant(nonce, counter, cid, action, param, duration_ms, expires, signer=SIGNER):
    inp = (b'HPSP2-GRANT\0' + UUID + nonce + counter.to_bytes(8, 'big') + cid.to_bytes(2, 'big')
           + bytes([action, param]) + duration_ms.to_bytes(4, 'big') + expires.to_bytes(8, 'big'))
    assert len(inp) == 84
    r, s = decode_dss_signature(KEY.sign(inp, ec.ECDSA(hashes.SHA256())))
    if s > N // 2: s = N - s                       # low-S, as the spec recommends
    return {'signer_hex': signer, 'counter': counter, 'expires': expires, 'sig_b64': r.to_bytes(32, 'big') + s.to_bytes(32, 'big')}

class Conn:
    def __init__(self, sock):
        self.s = sock; self.buf = b''; self.ids = 100; self.log = []
    def send(self, msg):
        b = cbor2.dumps(msg, canonical=True)
        self.s.sendall(struct.pack('>I', len(b)) + b)
    def cmd(self, op, data=None):
        self.ids += 1
        m = {'type': 'cmd', 'op': op, 'id': self.ids}
        if data is not None: m['data'] = data
        self.send(m); return self.ids
    def recv(self, timeout=3.0):
        end = time.time() + timeout
        while True:
            if len(self.buf) >= 4:
                L = struct.unpack('>I', self.buf[:4])[0]
                if len(self.buf) >= 4 + L:
                    raw = self.buf[4:4 + L]; self.buf = self.buf[4 + L:]
                    msg = cbor2.loads(raw)
                    canon = cbor2.dumps(msg, canonical=True) == raw
                    self.log.append((msg, canon, len(raw)))
                    if msg.get('type') == 'cmd' and msg.get('op') == 'heartbeat':
                        self.send({'type': 'rsp', 'op': 'heartbeat', 're': msg['id']})
                    return msg
            left = end - time.time()
            if left <= 0: return None
            self.s.settimeout(left)
            try:
                chunk = self.s.recv(4096)
            except socket.timeout:
                return None
            if not chunk: return None
            self.buf += chunk
    def wait(self, pred, timeout=4.0, keep=None):
        end = time.time() + timeout
        while time.time() < end:
            m = self.recv(end - time.time())
            if m is None: return None
            if keep is not None: keep.append(m)
            if pred(m): return m
        return None

def is_(t, op=None, re=None):
    return lambda m: m.get('type') == t and (op is None or m.get('op') == op) and (re is None or m.get('re') == re)

def hello_rsp(c, hello, resume_from):
    data = {'version': 1, 'max_msg': 1024, 'max_assembled': 8192, 'heartbeat_s': 2,
            'time': datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.000Z'), 'trust_epoch': 12}
    if resume_from is not None: data['resume_from'] = resume_from
    c.send({'type': 'rsp', 'op': 'hello', 're': hello['id'], 'data': data})

def main():
    dev = sys.argv[1] if len(sys.argv) > 1 else './hpsp_device'
    srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(('127.0.0.1', 0)); srv.listen(1)
    port = srv.getsockname()[1]
    # link_loss_grace_s = 0 so the test can see a latched unlock secured on session loss
    proc = subprocess.Popen([dev, '127.0.0.1', str(port), '3', '0'], stdout=open(os.path.join(ROOT, 'device_log.txt'), 'w'), stderr=subprocess.STDOUT)
    allmsgs = []
    try:
        srv.settimeout(5)
        # ---------------- session 1 ----------------
        s, _ = srv.accept(); c = Conn(s)
        hello = c.wait(is_('cmd', 'hello'))
        check(hello is not None, 'session 1: device sends hello first')
        d = hello['data']
        nonce1 = d['session_nonce_b64']
        check(d['device_id'] == V['deviceId'] and len(nonce1) == 32, 'hello: device_id and a 32-byte session value')
        check('mono_now' in d and 'grant_floor' in d and d['max_assembled'] >= 4096, 'hello: mono_now, grant_floor, max_assembled present')
        first = d.get('event_seq', {}).get('first')
        hello_rsp(c, hello, first)
        evs = []
        cred = c.wait(is_('evt', 'credential'), 3, evs)
        check(cred is not None and cred['data']['raw_hex'] == bytes.fromhex('c76a18c0') and cred['data']['bits'] == 26,
              'credential event: 26-bit card, raw bits c76a18c0 (the spec Wiegand example)')
        check(any(e.get('op') == 'boot' for e in evs), 'boot event replayed after hello')
        floor = d['grant_floor']; ctr = floor + 10
        now = int(time.time())

        g = sign_grant(nonce1, ctr, 2, 1, 0, 1000, now + 30)
        i = c.cmd('unlock', {'cid': 2, 'mode': 'timed', 'duration_ms': 1000, 'grant': g})
        r = c.wait(lambda m: m.get('re') == i)
        check(r and r['type'] == 'rsp' and r['data']['state'] == 'unlocked', 'unlock with a valid grant: unlocked')
        i = c.cmd('unlock', {'cid': 2, 'mode': 'timed', 'duration_ms': 1000, 'grant': g})
        r = c.wait(lambda m: m.get('re') == i)
        check(r and r['type'] == 'err' and r['data']['code'] == 'replay', 'the same grant again: err replay')

        bad_nonce = bytes([nonce1[0] ^ 1]) + nonce1[1:]
        i = c.cmd('unlock', {'cid': 2, 'mode': 'timed', 'duration_ms': 1000, 'grant': sign_grant(bad_nonce, ctr + 1, 2, 1, 0, 1000, now + 30)})
        r = c.wait(lambda m: m.get('re') == i)
        check(r and r['data'].get('code') == 'bad_signature', 'grant for another session value: err bad_signature')
        i = c.cmd('unlock', {'cid': 2, 'mode': 'timed', 'duration_ms': 1000, 'grant': sign_grant(nonce1, ctr + 2, 2, 1, 0, 1000, now - 60)})
        r = c.wait(lambda m: m.get('re') == i)
        check(r and r['data'].get('code') == 'expired', 'expired grant: err expired')
        i = c.cmd('unlock', {'cid': 2, 'mode': 'timed', 'duration_ms': 1000, 'grant': sign_grant(nonce1, ctr + 3, 2, 1, 0, 1000, now + 30, signer=b'\x11' * 32)})
        r = c.wait(lambda m: m.get('re') == i)
        check(r and r['data'].get('code') == 'unauthorized', 'unknown signer: err unauthorized')
        i = c.cmd('unlock', {'cid': 2, 'mode': 'timed', 'duration_ms': 50, 'grant': sign_grant(nonce1, ctr + 4, 2, 1, 0, 50, now + 30)})
        r = c.wait(lambda m: m.get('re') == i)
        check(r and r['data'].get('code') == 'bad_request', 'duration below 100 ms: err bad_request')
        i = c.cmd('unlock', {'cid': 2, 'mode': 'timed', 'duration_ms': 1000, 'grant': sign_grant(nonce1, ctr + 5, 2, 2, 0, 1000, now + 30)})
        r = c.wait(lambda m: m.get('re') == i)
        check(r and r['data'].get('code') == 'bad_signature', 'grant signed for a different action: err bad_signature')

        # fragments
        c.ids += 1; fid_cmd = c.ids
        whole = cbor2.dumps({'type': 'cmd', 'op': 'get_caps', 'id': fid_cmd}, canonical=True)
        for k, (a, b) in enumerate([(0, 6), (6, 14), (14, len(whole))]):
            c.send({'type': 'frag', 'data': {'fid': 3, 'total': len(whole), 'offset': a, 'data_b64': whole[a:b]}})
        r = c.wait(lambda m: m.get('re') == fid_cmd)
        check(r and r['type'] == 'rsp' and r['data']['components'][1]['door_release'] is True, 'get_caps sent in 3 fragments: joined and answered')
        c.send({'type': 'frag', 'data': {'fid': 4, 'total': 100000, 'offset': 0, 'data_b64': b'xx'}})
        r = c.wait(is_('err', 'frag'))
        check(r and r['data']['code'] == 'bad_request', 'fragment set above max_assembled: refused')

        hb = c.wait(is_('cmd', 'heartbeat'), 4)
        check(hb and 'mono_now' in hb['data'], 'heartbeat arrives within heartbeat_s and carries mono_now')
        tmo = lambda m: m.get('op') == 'lock_state' and m.get('data', {}).get('cause') == 'timeout'
        ls = any(tmo(m) for m, _, _ in c.log) or c.wait(tmo, 4) is not None
        check(ls, 'strike re-secures after 1 s: lock_state cause timeout')
        allmsgs += c.log
        seqs1 = sorted(m['seq'] for m, _, _ in c.log if m.get('type') == 'evt' and 'seq' in m)
        s.close()                                      # network fault: nothing was acknowledged

        # ---------------- session 2 ----------------
        s, _ = srv.accept(); c = Conn(s)
        hello = c.wait(is_('cmd', 'hello'))
        d = hello['data']; nonce2 = d['session_nonce_b64']
        check(nonce2 != nonce1, 'session 2: new session value')
        es = d.get('event_seq', {})
        check(es.get('first') == seqs1[0] and es.get('last') >= seqs1[-1], 'session 2: hello reports the unacknowledged events %s..%s' % (es.get('first'), es.get('last')))
        hello_rsp(c, hello, es.get('first'))
        got = []
        c.wait(lambda m: m.get('type') == 'evt' and m.get('seq') == es.get('last'), 4, got)
        rs = [m['seq'] for m in got if m.get('type') == 'evt' and 'seq' in m]
        check(rs == list(range(es['first'], es['last'] + 1)), 'all events replayed in order with no gaps (%d events)' % len(rs))
        check(any(m.get('op') == 'credential' for m in got), 'the card read from session 1 is delivered after the fault')
        c.send({'type': 'ack', 'data': {'seq': es['last']}})
        i = c.cmd('unlock', {'cid': 2, 'mode': 'timed', 'duration_ms': 1000, 'grant': sign_grant(nonce1, ctr + 20, 2, 1, 0, 1000, now + 30)})
        r = c.wait(lambda m: m.get('re') == i)
        check(r and r['data'].get('code') == 'bad_signature', 'a grant for session 1 is useless in session 2')
        i = c.cmd('unlock', {'cid': 2, 'mode': 'latched', 'grant': sign_grant(nonce2, ctr + 21, 2, 2, 0, 0, now + 30)})
        r = c.wait(lambda m: m.get('re') == i)
        check(r and r['type'] == 'rsp' and r['data']['state'] == 'unlocked', 'latched unlock with a session 2 grant')
        allmsgs += c.log
        s.close()                                      # session lost while latched

        # ---------------- session 3 ----------------
        s, _ = srv.accept(); c = Conn(s)
        hello = c.wait(is_('cmd', 'hello'))
        es = hello['data'].get('event_seq', {})
        hello_rsp(c, hello, es.get('first'))
        got = []
        c.wait(lambda m: m.get('type') == 'evt' and m.get('seq') == es.get('last'), 4, got)
        check(any(m.get('op') == 'lock_state' and m['data'].get('cause') == 'link_loss' for m in got),
              'latched unlock secured when the session was lost (link_loss), and reported')
        check(all(m.get('seq', 10**9) > seqs1[-1] for m in got if m.get('type') == 'evt'), 'acknowledged events are not sent again')
        i = c.cmd('goodbye', {'reason': 'shutdown'})
        r = c.wait(lambda m: m.get('re') == i)
        check(r and r['type'] == 'rsp', 'goodbye answered')
        allmsgs += c.log
        s.close()

        canon = all(ok for _, ok, _ in allmsgs)
        check(canon, 'every device message is deterministic CBOR (%d messages)' % len(allmsgs))
        check(all(n <= 1024 for _, _, n in allmsgs), 'every device message fits max_msg (largest %d bytes)' % max(n for _, _, n in allmsgs))
    finally:
        proc.terminate()
        try: proc.wait(3)
        except Exception: proc.kill()
    fails = [w for ok, w in results if not ok]
    print('\n%d scenario checks, %d failed' % (len(results), len(fails)))
    sys.exit(1 if fails else 0)

if __name__ == '__main__':
    main()
