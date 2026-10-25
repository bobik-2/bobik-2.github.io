// load_clinic_key, create_clinic_key, grant_clinic_access (F4; rozstrzygnięcia 3 i 14; B-D4).
import { toB64url } from "../b64.js";
import { sha256Hex } from "../bytes.js";
import { generateClinicKey, openClinicGrant, sealClinicGrant } from "../crypto/clinic.js";
import { importP256Pair, importP256Public } from "../crypto/keys.js";
import { VaultError } from "../errors.js";
import { fingerprint } from "../fingerprint.js";
import { PROMPTS } from "../prompts.js";
import { bytes, label, posInt, uuid } from "../validate.js";

export const loadClinicKey = {
  needs: "unlocked",
  interactive: false,
  parse: (req) => ({
    clinicId: posInt(req.clinic_id),
    clinicKeyId: uuid(req.clinic_key_id),
    spki: bytes(req.clinic_public_key_der, { max: 1024 }),
    grant: bytes(req.wrapped_private, { min: 82, max: 1024 }),
  }),
  async run(ctx, { clinicId, clinicKeyId, spki, grant }) {
    const session = ctx.session;
    const doctor = session.doctor;
    const publicKey = await importP256Public(spki);
    const spkiHex = await sha256Hex(spki);
    const pkcs8 = await openClinicGrant(doctor.pair, { clinicId, doctorId: doctor.doctorId, clinicSpkiHex: spkiHex, blob: grant });
    const pair = await importP256Pair(pkcs8, publicKey); // zeruje pkcs8
    // Bajty grantu zostają: grant_clinic_access otwiera go ponownie zamiast eksportować klucz (spike).
    session.clinics.set(clinicKeyId, { clinicId, pair, spki, spkiHex, grant });
    return { clinic_key_id: clinicKeyId, fingerprint: await fingerprint(spki) };
  },
};

export const createClinicKey = {
  needs: "unlocked",
  interactive: true,
  parse: (req) => ({ clinicId: posInt(req.clinic_id), label: label(req.clinic_label) }),
  async run(ctx, { clinicId, label }) {
    const doctor = ctx.session.doctor;
    await ctx.ask(PROMPTS.createClinic(label, clinicId));
    const { spki, pkcs8 } = await generateClinicKey();
    try {
      const blob = await sealClinicGrant(doctor.pair.publicKey, {
        clinicId,
        doctorId: doctor.doctorId,
        clinicSpkiHex: await sha256Hex(spki),
        pkcs8,
      });
      // Klucz kliniki trafia do pamięci dopiero przez load_clinic_key po zapisie na serwerze (F4).
      return { clinic_public_key_der: toB64url(spki), wrapped_private: toB64url(blob), fingerprint: await fingerprint(spki) };
    } finally {
      pkcs8.fill(0);
    }
  },
};

export const grantClinicAccess = {
  needs: "unlocked",
  interactive: true,
  parse: (req) => ({
    clinicKeyId: uuid(req.clinic_key_id),
    recipientId: posInt(req.recipient_doctor_id),
    label: label(req.recipient_label),
    recipientSpki: bytes(req.recipient_public_key_der, { max: 1024 }),
  }),
  async run(ctx, { clinicKeyId, recipientId, label, recipientSpki }) {
    const session = ctx.session;
    const doctor = session.doctor;
    const clinic = session.clinics.get(clinicKeyId);
    if (!clinic) throw new VaultError("clinic_key_not_loaded");
    const recipientKey = await importP256Public(recipientSpki);
    // Odcisk liczony w sejfie z klucza, do którego sejf zaraz zapakuje grant (B-D4).
    const recipientFingerprint = await fingerprint(recipientSpki);
    await ctx.ask(PROMPTS.grantAccess(label, recipientFingerprint, recipientId));
    const pkcs8 = await openClinicGrant(doctor.pair, {
      clinicId: clinic.clinicId,
      doctorId: doctor.doctorId,
      clinicSpkiHex: clinic.spkiHex,
      blob: clinic.grant,
    });
    try {
      const blob = await sealClinicGrant(recipientKey, { clinicId: clinic.clinicId, doctorId: recipientId, clinicSpkiHex: clinic.spkiHex, pkcs8 });
      return { wrapped_private: toB64url(blob), recipient_fingerprint: recipientFingerprint };
    } finally {
      pkcs8.fill(0);
    }
  },
};
