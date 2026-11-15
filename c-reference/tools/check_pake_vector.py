"""Re-derive the HPSP commissioning vector and compare it with the one in the specification."""
import json, os, subprocess, sys, tempfile
here = os.path.dirname(os.path.abspath(__file__)); root = os.path.dirname(here)
sys.path.insert(0, here)
import spake2plus
assert spake2plus.rfc_check(), 'RFC 9383 vector not reproduced'
tmp = tempfile.mktemp(suffix='.json')
subprocess.check_call([sys.executable, os.path.join(here, 'hpsp_pake_vector.py'), tmp], stdout=subprocess.DEVNULL)
mine = json.load(open(tmp)); spec = json.load(open(os.path.join(root, 'vectors/spec_vectors.json')))['pake']
bad = [k for k in spec if spec[k] != mine.get(k)]
print('RFC 9383 vector reproduced; HPSP commissioning vector', 'matches the specification' if not bad else 'DIFFERS in %s' % bad)
sys.exit(1 if bad else 0)
