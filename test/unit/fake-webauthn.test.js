import { expect, it } from "vitest";
import { toB64url } from "../../src/b64.js";
import { evaluatePrf, registerCredential } from "../../src/webauthn.js";
import { fakeAuthenticators } from "../helpers/fake-webauthn.js";

const args = (salt, excludeIds = []) => ({ rpId: "localhost", rpName: "t", userId: new Uint8Array(4), userName: "u", displayName: "U", salt, excludeIds });

it("atrapa: PRF przy create() = PRF przy get() z tą samą solą; inna sól -> inny wynik", async () => {
  const a = fakeAuthenticators();
  a.insertNew();
  const salt = new Uint8Array(32).fill(1);
  const reg = await registerCredential(a.credentials, args(salt));
  const same = await evaluatePrf(a.credentials, { rpId: "localhost", keys: [{ credentialId: reg.credentialId, salt }] });
  expect(same.prfFirst).toEqual(reg.prfFirst);
  const other = await evaluatePrf(a.credentials, { rpId: "localhost", keys: [{ credentialId: reg.credentialId, salt: new Uint8Array(32).fill(2) }] });
  expect(other.prfFirst).not.toEqual(reg.prfFirst);
});

it("atrapa: prfAtCreate=false -> create() bez prf.results", async () => {
  const a = fakeAuthenticators({ prfAtCreate: false });
  a.insertNew();
  expect((await registerCredential(a.credentials, args(new Uint8Array(32)))).prfFirst).toBe(null);
});

it("atrapa: ten sam klucz w excludeCredentials -> already_registered; wyjęty klucz -> not_allowed", async () => {
  const a = fakeAuthenticators();
  a.insertNew();
  const reg = await registerCredential(a.credentials, args(new Uint8Array(32)));
  await expect(registerCredential(a.credentials, args(new Uint8Array(32), [reg.credentialId]))).rejects.toMatchObject({ code: "already_registered" });
  a.remove();
  const keys = [{ credentialId: reg.credentialId, salt: new Uint8Array(32) }];
  await expect(evaluatePrf(a.credentials, { rpId: "localhost", keys })).rejects.toMatchObject({ code: "not_allowed" });
});

it("atrapa: klucz z wektora daje stały PRF", async () => {
  const a = fakeAuthenticators();
  const rawId = new Uint8Array([9, 9]);
  a.addFixed(rawId, new Uint8Array(32).fill(4));
  a.insert(toB64url(rawId));
  const res = await evaluatePrf(a.credentials, { rpId: "x", keys: [{ credentialId: rawId, salt: new Uint8Array(32) }] });
  expect(res.prfFirst).toEqual(new Uint8Array(32).fill(4));
});
