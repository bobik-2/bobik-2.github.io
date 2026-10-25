// open (F5): DEK wywiadów z clinic_wrap, pola Sealed i SealedToClinic. Limit sprawdzany dla całego
// żądania przed pierwszym odszyfrowaniem; błędy pojedynczych elementów idą per element.
import { importDek, openClinicWrap, openSealed, openStc, stcKeyId } from "../crypto/fields.js";
import { VaultError } from "../errors.js";
import { LIMITS } from "../limits.js";
import { bytes, field, list, oneOf, posInt, uuid } from "../validate.js";

const MAX = LIMITS.OPEN_MAX_ITEMS;

function parseItem(item) {
  const kind = oneOf(item.kind, ["sealed", "stc"]);
  const common = { kind, field: field(item.field), blob: bytes(item.blob, { max: 1 << 20 }) };
  return kind === "sealed" ? { ...common, interviewId: uuid(item.interview_id) } : { ...common, clinicId: posInt(item.clinic_id) };
}

export const open = {
  needs: "unlocked",
  interactive: false,
  parse(req) {
    const interviews = list(req.interviews, { max: MAX }, (e) => ({
      interviewId: uuid(e.interview_id),
      interviewKeyId: uuid(e.interview_key_id),
      clinicKeyId: uuid(e.clinic_key_id),
      clinicWrap: bytes(e.clinic_wrap, { max: 1024 }),
    }));
    if (new Set(interviews.map((e) => e.interviewId)).size !== interviews.length) throw new VaultError("bad_args");
    return { interviews, items: list(req.items, { max: MAX }, parseItem) };
  },
  async run(ctx, { interviews, items }) {
    const session = ctx.session;
    ctx.charge({ interviewIds: interviews.map((e) => e.interviewId), stc: items.filter((i) => i.kind === "stc").length });
    const deks = new Map();
    for (const entry of interviews) deks.set(entry.interviewId, await dekFor(session, entry));
    const values = [];
    for (const item of items) values.push(await openItem(session, deks, item));
    return { values };
  },
};

// DEK z pamięci, gdy ten sam InterviewKey; inaczej z clinic_wrap (i zapis w sesji).
async function dekFor(session, entry) {
  const cached = session.deks.get(entry.interviewId);
  if (cached && cached.interviewKeyId === entry.interviewKeyId) return { entry, key: cached.key };
  const clinic = session.clinics.get(entry.clinicKeyId);
  if (!clinic) return { error: "clinic_key_not_loaded" };
  try {
    const key = await importDek(await openClinicWrap(clinic.pair, entry.interviewId, entry.clinicWrap));
    session.deks.set(entry.interviewId, { interviewKeyId: entry.interviewKeyId, key });
    return { entry, key };
  } catch (e) {
    // VaultError z openClinicWrap/importDek (bad_blob, decrypt_failed) dotyczy pól tego wywiadu.
    if (e instanceof VaultError) return { error: e.code };
    throw e;
  }
}

async function openItem(session, deks, item) {
  try {
    if (item.kind === "sealed") {
      const dek = deks.get(item.interviewId);
      if (!dek) return { ok: false, error: "unknown_interview" };
      if (dek.error) return { ok: false, error: dek.error };
      const value = await openSealed(dek.key, {
        interviewId: item.interviewId,
        interviewKeyId: dek.entry.interviewKeyId,
        field: item.field,
        blob: item.blob,
      });
      return { ok: true, value };
    }
    const clinic = session.clinics.get(stcKeyId(item.blob));
    if (!clinic) return { ok: false, error: "clinic_key_not_loaded" };
    if (clinic.clinicId !== item.clinicId) return { ok: false, error: "key_mismatch" };
    return { ok: true, value: await openStc(clinic.pair, item) };
  } catch (e) {
    // VaultError = kod elementu (bad_blob, key_mismatch, decrypt_failed); reszta to błąd sejfu.
    if (e instanceof VaultError) return { ok: false, error: e.code };
    throw e;
  }
}
