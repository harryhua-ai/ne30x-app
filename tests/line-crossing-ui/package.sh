#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$ROOT"
if ! git diff --quiet HEAD -- apps/line-crossing/ui tests/line-crossing-ui; then
    echo "refusing to package: apps/line-crossing/ui or tests/line-crossing-ui differ from HEAD; commit the source first" >&2
    exit 1
fi
source_commit=$(git rev-parse HEAD)
task_tmpdir=$(mktemp -d "${TMPDIR:-/tmp}/line-crossing-ui.XXXXXX")
trap 'rm -rf "$task_tmpdir"' EXIT HUP INT TERM
python3 - "$task_tmpdir" <<'PY'
from pathlib import Path
import hashlib
import json
import sys
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
root=Path(sys.argv[1])
key=ec.derive_private_key(1, ec.SECP256R1())
spki=key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
(root/'test-signer.pem').write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
(root/'test-signer.pem').chmod(0o600)
(root/'trust.json').write_text(json.dumps({'version':1,'comment':'NON-PRODUCTION public d=1 test identity','publishers':{'test-publisher':{'spki_der_hex':spki.hex(),'spki_sha256':hashlib.sha256(spki).hexdigest()}}},indent=2)+'\n')
(root/'trust.json').chmod(0o600)
evidence=Path('tests/line-crossing-ui/evidence')
evidence.mkdir(exist_ok=True)
(evidence/'test-publisher.spki.der').write_bytes(spki)
PY
python3 package/sidecar/neui_pack_v1.py \
    --asset-root tests/line-crossing-ui/.build/production \
    --out docs/evidence/line-crossing-ui/line-crossing.neui \
    --key "$task_tmpdir/test-signer.pem" \
    --publisher-id test-publisher --app-id line-crossing --version 1.0.0 \
    --native-package docs/evidence/spec-v3/golden.neapp.v3 \
    --native-trust "$task_tmpdir/trust.json"
python3 package/sidecar/neui_verify_v1.py \
    --bundle docs/evidence/line-crossing-ui/line-crossing.neui \
    --trust "$task_tmpdir/trust.json" \
    --native-package docs/evidence/spec-v3/golden.neapp.v3 \
    --native-trust "$task_tmpdir/trust.json" \
    --compact > "$task_tmpdir/verification-output.txt"
python3 - "$task_tmpdir/verification-output.txt" docs/evidence/line-crossing-ui/neui-verification.json <<'PY'
from pathlib import Path
import json
import sys
report=json.loads(Path(sys.argv[1]).read_text().splitlines()[0])
if report.get('result') != 'PASS' or not report.get('native_binding_trusted'):
    raise SystemExit('NEUI verification did not PASS with a trusted native binding')
Path(sys.argv[2]).write_text(json.dumps(report, indent=2, sort_keys=True)+'\n')
PY
python3 - "$task_tmpdir/verification-output.txt" "$source_commit" <<'PY'
from pathlib import Path
import hashlib
import json
import sys
report=json.loads(Path(sys.argv[1]).read_text().splitlines()[0])
source_commit=sys.argv[2]
native=Path('docs/evidence/spec-v3/golden.neapp.v3').read_bytes()
provenance={
    'bundle_len': report['bundle_len'],
    'bundle_path': 'docs/evidence/line-crossing-ui/line-crossing.neui',
    'bundle_sha256': report['bundle_sha256'],
    'files': report['files'],
    'format': report['format'],
    'generator': 'neui_pack_v1.py 1.0.0',
    'manifest': {
        'app_id': 'line-crossing',
        'file_count': report['file_count'],
        'host_ui_abi': report['host_ui_abi'],
        'publisher_id': report['publisher_id'],
        'sidecar_version': report['sidecar_version'],
    },
    'native_binding': {
        'native_offline_verified': bool(report.get('native_binding_trusted')),
        'native_package_path': 'docs/evidence/spec-v3/golden.neapp.v3',
        'native_package_sha256': hashlib.sha256(native).hexdigest(),
        'native_package_sha256_note': 'whole-file digest recorded for traceability only; the wire binding value is native_tbs_sha256, never this DER-dependent digest',
        'native_publisher_key_match': True,
        'native_tbs_sha256': report['native_tbs_sha256'],
    },
    'non_production_trust_root': 'signing key is a NON-PRODUCTION dev/test identity; not a production trust anchor and never a device production root',
    'signature': 'ECDSA over secp256r1 (P-256), SHA-256, strict DER',
    'signature_len': report['signature_len'],
    'signer_spki_sha256': report['publisher_key_sha256'],
    'source_commit': source_commit,
    'spec_authority': 'ne301 issue #79 \u00a712 (frozen Sidecar v1 wire, 2026-10-15)',
    'tbs_len': report['tbs_len'],
    'ui_tbs_sha256': report['ui_tbs_sha256'],
}
Path('docs/evidence/line-crossing-ui/line-crossing.neui.provenance.json').write_text(json.dumps(provenance, indent=2, sort_keys=True)+'\n')
PY
cat docs/evidence/line-crossing-ui/neui-verification.json
