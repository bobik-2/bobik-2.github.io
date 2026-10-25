// Konteksty wiążące szyfrogramy z miejscem użycia (spec B, „Formaty"; bobik-2 keyvault/context.py).
// Zmiana formatu = nowa wersja (/v2|, nowy bajt wersji), nigdy edycja istniejącego.

export const doctorKekInfo = (doctorId, credential) => `bobik/doctor-kek/v1|doctor=${doctorId}|credential=${credential}`;

export const doctorWrapAad = (doctorId, credential, spkiHex) =>
  `bobik/doctor-wrap/v1|doctor=${doctorId}|credential=${credential}|doctor_spki_sha256=${spkiHex}`;

export const clinicGrantInfo = (clinicId, doctorId, clinicSpkiHex) =>
  `bobik/clinic-grant/v1|clinic=${clinicId}|doctor=${doctorId}|clinic_spki_sha256=${clinicSpkiHex}`;

export const dekInfo = (interviewId) => `bobik/dek/v1|interview=${interviewId}`;

export const sealedContext = (interviewId, field) => `interview=${interviewId}|field=${field}`;

export const stcContext = (clinicId, field) => `clinic=${clinicId}|field=${field}`;

export const STC_INFO_PREFIX = "bobik/stc/v1|";
