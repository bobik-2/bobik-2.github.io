import { expect, it } from "vitest";
import {
  clinicGrantInfo,
  dekInfo,
  doctorKekInfo,
  doctorWrapAad,
  sealedContext,
  STC_INFO_PREFIX,
  stcContext,
} from "../../src/crypto/context.js";
import { BOBIK2 } from "../helpers/vectors.js";

const HEX = "9b1c".padEnd(64, "0");
const IV = "3f2a9c1e-5b7d-4e8f-9a0b-1c2d3e4f5a6b";

it("konteksty F2–F5 dosłownie jak w specu", () => {
  expect(doctorKekInfo(17, "q8Zr")).toBe("bobik/doctor-kek/v1|doctor=17|credential=q8Zr");
  expect(doctorWrapAad(17, "q8Zr", HEX)).toBe(`bobik/doctor-wrap/v1|doctor=17|credential=q8Zr|doctor_spki_sha256=${HEX}`);
  expect(clinicGrantInfo(3, 17, HEX)).toBe(`bobik/clinic-grant/v1|clinic=3|doctor=17|clinic_spki_sha256=${HEX}`);
  expect(sealedContext(IV, "interviews.Interview.age")).toBe(`interview=${IV}|field=interviews.Interview.age`);
  expect(stcContext(3, "core.WithdrawalLog.reason")).toBe("clinic=3|field=core.WithdrawalLog.reason");
  expect(STC_INFO_PREFIX).toBe("bobik/stc/v1|");
});

it("dekInfo zgodny z bobik-2 (keyvault.context.dek_info)", () => {
  expect(dekInfo(BOBIK2.interview_id)).toBe(BOBIK2.clinic_wrap.info);
});
