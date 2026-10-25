// grant_lease (F6): lekarz zatwierdza w sejfie rodzaj, wywiad i czas; DEK pod kluczem dzierżawy.
// Pochodzenie klucza dzierżawy nie jest weryfikowane (rozstrzygnięcie 2); study_code to etykieta (B-R8).
import { toB64url } from "../b64.js";
import { openClinicWrap } from "../crypto/fields.js";
import { importLeaseKey, wrapDekForLease } from "../crypto/lease.js";
import { VaultError } from "../errors.js";
import { PROMPTS } from "../prompts.js";
import { bytes, oneOf, optPosInt, text, uuid } from "../validate.js";

export const grantLease = {
  needs: "unlocked",
  interactive: true,
  parse(req) {
    const kind = oneOf(req.kind, ["addendum", "repair"]);
    const sessionSeq = optPosInt(req.session_seq);
    const agentRunId = optPosInt(req.agent_run_id);
    const target = kind === "addendum" ? sessionSeq === null && agentRunId === null : (sessionSeq === null) !== (agentRunId === null);
    if (!target) throw new VaultError("bad_args");
    return {
      interviewId: uuid(req.interview_id),
      interviewKeyId: uuid(req.interview_key_id),
      clinicKeyId: uuid(req.clinic_key_id),
      clinicWrap: bytes(req.clinic_wrap, { max: 1024 }),
      studyCode: text(req.study_code, 64),
      kind,
      sessionSeq,
      agentRunId,
      leaseSpki: bytes(req.lease_public_key_der, { max: 2048 }),
    };
  },
  async run(ctx, a) {
    const clinic = ctx.session.clinics.get(a.clinicKeyId);
    if (!clinic) throw new VaultError("clinic_key_not_loaded");
    const leaseKey = await importLeaseKey(a.leaseSpki);
    const usage = { interviewIds: [a.interviewId], stc: 0 };
    ctx.charge(usage, { record: false }); // limit przed pytaniem, koszt dopiero po zatwierdzeniu (P7)
    await ctx.ask(PROMPTS.grantLease(a));
    ctx.charge(usage);
    const dek = await openClinicWrap(clinic.pair, a.interviewId, a.clinicWrap);
    return { rsa_wrapped_dek: toB64url(await wrapDekForLease(leaseKey, dek)) }; // zeruje dek
  },
};
