// Tabela operacji protokołu (spec B, „Operacje"). Klucze = nazwy `op`.
import { hello, lock } from "./basic.js";
import { createClinicKey, grantClinicAccess, loadClinicKey } from "./clinic.js";
import { addCredential, register, unlock } from "./doctor.js";
import { grantLease } from "./lease.js";
import { open } from "./open.js";

export const OPS = Object.freeze({
  hello,
  register,
  unlock,
  add_credential: addCredential,
  load_clinic_key: loadClinicKey,
  create_clinic_key: createClinicKey,
  grant_clinic_access: grantClinicAccess,
  open,
  grant_lease: grantLease,
  lock,
});
