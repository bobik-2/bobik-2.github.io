// register, unlock, add_credential (spec B, „Operacje"; F1–F3; B-D5; rozstrzygnięcia 6 i 16).
// Każde wywołanie WebAuthn następuje zaraz po kliknięciu przycisku w sejfie (aktywacja użytkownika
// w iframe'ie), bez innych await pomiędzy.
import { toB64url } from "../b64.js";
import { random, sha256Hex, utf8 } from "../bytes.js";
import { doctorWrapAad } from "../crypto/context.js";
import { deriveKek, generateDoctorKey, unwrapDoctorKey, wrapDoctorKey } from "../crypto/doctor.js";
import { importP256Public } from "../crypto/keys.js";
import { VaultError } from "../errors.js";
import { fingerprint } from "../fingerprint.js";
import { PROMPTS } from "../prompts.js";
import { bytes, list, posInt, text } from "../validate.js";
import { evaluatePrf, registerCredential } from "../webauthn.js";

export const RP_NAME = "Sejf kluczy bobik";
const PRF_SALT_LEN = 32;
const userHandle = (doctorId) => utf8(`bobik-doctor-${doctorId}`);

function parseCredentials(value) {
  return list(value, { min: 1, max: 10 }, (c) => ({
    credentialId: bytes(c.credential_id, { min: 1, max: 1023 }),
    prfSalt: bytes(c.prf_salt, { min: PRF_SALT_LEN, max: PRF_SALT_LEN }),
    wrapped: bytes(c.wrapped_private, { min: 29, max: 1024 }),
  }));
}

const parseDoctorKey = (req) => ({
  doctorId: posInt(req.doctor_id),
  spki: bytes(req.public_key_der, { max: 1024 }),
  credentials: parseCredentials(req.credentials),
});

// Jeden nowy YubiKey: create() z PRF; bez prf.results (firmware < 5.8) drugie dotknięcie get().
async function enroll(ctx, { doctorId, displayName, excludeIds, prompt, touchPrompt }) {
  await ctx.ask(prompt);
  const salt = random(PRF_SALT_LEN);
  const reg = await registerCredential(ctx.credentials, {
    rpId: ctx.rpId,
    rpName: RP_NAME,
    userId: userHandle(doctorId),
    userName: `lekarz-${doctorId}`,
    displayName,
    salt,
    excludeIds,
    signal: ctx.signal,
  });
  let prf = reg.prfFirst;
  if (!prf) {
    await ctx.ask(touchPrompt);
    prf = (await evaluatePrf(ctx.credentials, { rpId: ctx.rpId, keys: [{ credentialId: reg.credentialId, salt }], signal: ctx.signal })).prfFirst;
  }
  return { credentialId: reg.credentialId, salt, prf };
}

async function wrapFor(privateKey, doctorId, spkiHex, enrolled) {
  const credential = toB64url(enrolled.credentialId);
  const kek = await deriveKek(enrolled.prf, doctorId, credential); // zeruje enrolled.prf
  const blob = await wrapDoctorKey(privateKey, kek, doctorWrapAad(doctorId, credential, spkiHex));
  return { credential_id: credential, prf_salt: toB64url(enrolled.salt), wrapped_private: toB64url(blob) };
}

// Jedno get() z evalByCredential: odpowiada włożony klucz, wrap wybierany po rawId (spike 1b).
async function unwrapWith(ctx, { doctorId, spkiHex, credentials }, { extractable }) {
  const { index, prfFirst } = await evaluatePrf(ctx.credentials, {
    rpId: ctx.rpId,
    keys: credentials.map((c) => ({ credentialId: c.credentialId, salt: c.prfSalt })),
    signal: ctx.signal,
  });
  const chosen = credentials[index];
  const credential = toB64url(chosen.credentialId);
  const kek = await deriveKek(prfFirst, doctorId, credential);
  return unwrapDoctorKey(chosen.wrapped, kek, doctorWrapAad(doctorId, credential, spkiHex), { extractable });
}

export const register = {
  needs: "ready",
  interactive: true,
  bindsEpoch: true, // blokada w trakcie rejestracji -> locked zamiast wyniku (P3, przegląd 5–8 L3)
  parse: (req) => ({ doctorId: posInt(req.doctor_id), displayName: text(req.display_name, 200) }),
  async run(ctx, { doctorId, displayName }) {
    const enrolled = [];
    try {
      for (const n of [1, 2]) {
        enrolled.push(
          await enroll(ctx, {
            doctorId,
            displayName,
            excludeIds: enrolled.map((e) => e.credentialId),
            prompt: PROMPTS.registerKey(n, displayName),
            touchPrompt: PROMPTS.secondTouch(n),
          }),
        );
      }
      // Para eksportowalna wyłącznie na dwa wrapKey; sejf zostaje zablokowany (decyzja planu P1).
      const { pair, spki } = await generateDoctorKey();
      const spkiHex = await sha256Hex(spki);
      const credentials = [];
      for (const e of enrolled) credentials.push(await wrapFor(pair.privateKey, doctorId, spkiHex, e));
      return { public_key_der: toB64url(spki), fingerprint: await fingerprint(spki), credentials };
    } finally {
      for (const e of enrolled) e.prf.fill(0);
    }
  },
};

export const unlock = {
  needs: "ready",
  interactive: true,
  parse: parseDoctorKey,
  async run(ctx, { doctorId, spki, credentials }, epoch) {
    const publicKey = await importP256Public(spki);
    const spkiHex = await sha256Hex(spki);
    await ctx.ask(PROMPTS.unlock());
    const privateKey = await unwrapWith(ctx, { doctorId, spkiHex, credentials }, { extractable: false });
    const fp = await fingerprint(spki);
    ctx.unlockWith(epoch, { doctorId, pair: { privateKey, publicKey }, spki, spkiHex, fingerprint: fp });
    return { fingerprint: fp };
  },
};

export const addCredential = {
  needs: "unlocked",
  interactive: true,
  parse: parseDoctorKey,
  async run(ctx, { doctorId, spki, credentials }) {
    const doctor = ctx.session.doctor;
    const spkiHex = await sha256Hex(spki);
    if (doctorId !== doctor.doctorId || spkiHex !== doctor.spkiHex) throw new VaultError("bad_args");
    await ctx.ask(PROMPTS.addExisting());
    // F3: chwilowa kopia eksportowalna wyłącznie do wrapKey dla nowego klucza, potem porzucona.
    const exportable = await unwrapWith(ctx, { doctorId, spkiHex, credentials }, { extractable: true });
    const added = await enroll(ctx, {
      doctorId,
      displayName: `Lekarz ${doctorId}`,
      excludeIds: credentials.map((c) => c.credentialId),
      prompt: PROMPTS.addNew(),
      touchPrompt: PROMPTS.secondTouch(3),
    });
    try {
      return { credential: await wrapFor(exportable, doctorId, spkiHex, added) };
    } finally {
      added.prf.fill(0);
    }
  },
};
