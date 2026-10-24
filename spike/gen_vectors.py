"""SPIKE (throwaway): wektory z kodu bobik-2 do sprawdzenia zgodności sejfu.

Uruchom z katalogu bobik-2:
    uv run python ../bobik-sejf/spike/gen_vectors.py > ../bobik-sejf/spike/vectors.json
"""

import base64
import json
import os
import uuid

from bobik2.crypto import envelope, hpke


def b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


clinic = hpke.generate_p256()
clinic_key_id = uuid.UUID("11111111-2222-3333-4444-555555555555")
clinic_id = 7
interview_id = 42
interview_key_id = uuid.UUID("66666666-7777-8888-9999-aaaaaaaaaaaa")
dek = os.urandom(32)
field = "interviews.Interview.age"
value = json.dumps({"lata": 54, "uwagi": "żółć"}, separators=(",", ":"), ensure_ascii=False).encode()

dek_info = f"bobik/dek/v1|interview={interview_id}".encode()
clinic_wrap = hpke.hpke_seal(clinic.public_key(), info=dek_info, plaintext=dek)
sealed = envelope.aead_seal(
    dek=dek, key_id=interview_key_id,
    context=f"interview={interview_id}|field={field}".encode(), plaintext=value,
)
stc = hpke.stc_seal(
    clinic.public_key(), key_id=clinic_key_id,
    context=f"clinic={clinic_id}|field={field}".encode(), plaintext=value,
)

print(json.dumps({
    "clinic_private_pkcs8": b64(hpke.private_key_der(clinic)),
    "clinic_public_spki": b64(hpke.public_key_der(clinic.public_key())),
    "clinic_id": clinic_id,
    "interview_id": interview_id,
    "field": field,
    "dek": b64(dek),
    "clinic_wrap": b64(clinic_wrap),
    "sealed": b64(sealed),
    "stc": b64(stc),
    "plaintext": value.decode(),
}, ensure_ascii=False, indent=2))
