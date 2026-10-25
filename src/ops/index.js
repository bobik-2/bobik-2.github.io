// Tabela operacji protokołu (spec B, „Operacje"). Klucze = nazwy `op`.
import { hello, lock } from "./basic.js";
import { addCredential, register, unlock } from "./doctor.js";

export const OPS = Object.freeze({
  hello,
  register,
  unlock,
  add_credential: addCredential,
  lock,
});
