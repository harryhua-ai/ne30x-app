#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$ROOT"
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
    > docs/evidence/line-crossing-ui/neui-verification.json
cat docs/evidence/line-crossing-ui/neui-verification.json
