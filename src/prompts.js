// Teksty UI sejfu (po polsku). Etykiety od panelu są nieuwierzytelnione (B-R8), więc UI wstawia
// je wyłącznie przez textContent; kryptograficznie związane są tylko identyfikatory i klucze.
import { LIMITS } from "./limits.js";

const STATUS = { locked: "Sejf zablokowany", unlocked: "Sejf odblokowany" };
const REFUSAL = {
  revoked: "Ta wersja sejfu jest unieważniona. Panel musi przejść na nowszą wersję.",
  browser_blocked: "Ta przeglądarka nie jest obsługiwana (Safari/WebKit). Użyj Chrome, Edge albo Firefoksa z kluczem sprzętowym.",
  top_level: "Sejf działa wyłącznie osadzony w panelu bobik-2.",
};

export const statusText = (view) => (view.state === "refusing" ? REFUSAL[view.refusal] : STATUS[view.state]);

export function formatCounters({ interviews, stc, idleLeftMs }) {
  return `Wywiady: ${interviews}/${LIMITS.INTERVIEWS_PER_UNLOCK} · wartości kliniki: ${stc}/${LIMITS.STC_PER_UNLOCK} · blokada za ${Math.ceil(idleLeftMs / 60_000)} min`;
}

const TOUCH = "Kliknij przycisk, dotknij klucza i podaj jego PIN.";

export const PROMPTS = {
  registerKey: (n, displayName) => ({
    kind: "register_key",
    title: `Rejestracja klucza ${n} z 2`,
    untrusted: [0],
    lines: [`Lekarz — nazwa z panelu (niezweryfikowana): ${displayName}`, n === 1 ? "Włóż pierwszy klucz sprzętowy (YubiKey)." : "Wyjmij pierwszy klucz i włóż drugi (zapasowy).", TOUCH],
    confirm: `Zarejestruj klucz ${n}`,
    cancel: "Anuluj",
  }),
  secondTouch: (n) => ({
    kind: "second_touch",
    title: `Klucz ${n}: drugie dotknięcie`,
    lines: ["Ten klucz nie zwrócił sekretu przy rejestracji (firmware starszy niż 5.8).", TOUCH],
    confirm: "Dotknij ponownie",
    cancel: "Anuluj",
  }),
  unlock: () => ({
    kind: "unlock",
    title: "Odblokowanie sejfu",
    lines: ["Włóż jeden ze swoich kluczy sprzętowych.", TOUCH],
    confirm: "Odblokuj",
    cancel: "Anuluj",
  }),
  addExisting: () => ({
    kind: "add_existing",
    title: "Dodanie klucza — krok 1 z 2",
    lines: ["Włóż jeden z już zarejestrowanych kluczy.", TOUCH],
    confirm: "Potwierdź istniejącym kluczem",
    cancel: "Anuluj",
  }),
  addNew: () => ({
    kind: "add_new",
    title: "Dodanie klucza — krok 2 z 2",
    lines: ["Wyjmij zarejestrowany klucz i włóż nowy.", TOUCH],
    confirm: "Zarejestruj nowy klucz",
    cancel: "Anuluj",
  }),
  // Identyfikatory związane kryptograficznie (kontekst grantu `clinic=`/`doctor=`, info clinic_wrap)
  // stoją przed etykietami, które panel podaje bez uwierzytelnienia (przegląd 9–10, L-1 i M-2).
  createClinic: (label, clinicId) => ({
    kind: "create_clinic",
    title: "Nowy klucz kliniki",
    bound: [],
    untrusted: [0],
    lines: [
      `Klinika nr ${clinicId} — nazwa z panelu (niezweryfikowana): ${label}`,
      "Klucz prywatny kliniki powstaje w sejfie i nie opuszcza go w postaci jawnej.",
    ],
    confirm: "Załóż klucz",
    cancel: "Anuluj",
  }),
  grantAccess: (label, fingerprint, recipientId) => ({
    kind: "grant_access",
    title: "Nadanie dostępu do kliniki",
    bound: [0],
    untrusted: [1],
    // Odcisk (liczony w sejfie) zawsze w pierwszym wierszu, przed nieuwierzytelnioną etykietą (M-2).
    lines: [
      `Odcisk klucza odbiorcy: ${fingerprint}`,
      `Odbiorca: lekarz nr ${recipientId} — nazwa z panelu (niezweryfikowana): ${label}`,
      "Porównaj odcisk i numer lekarza z tym, co odbiorca odczytał ze swojego sejfu — przez telefon albo osobiście, nie przez panel.",
    ],
    confirm: "Odcisk zgodny — nadaj dostęp",
    cancel: "Odcisk niezgodny — anuluj",
  }),
  // Z wywiadem wiąże dzierżawę tylko interview_id (info clinic_wrap); study_code, rodzaj i czas
  // deklaruje panel, a długość dzierżawy ustala serwer (I-1).
  grantLease: ({ kind, interviewId, studyCode, sessionSeq, agentRunId }) => ({
    kind: "grant_lease",
    title: kind === "addendum" ? "Odblokowanie dopisku" : "Dzierżawa naprawcza",
    bound: [0],
    untrusted: [1],
    lines: [
      `Wywiad: ${interviewId}`,
      `Kod wywiadu z panelu: ${studyCode}`,
      kind === "addendum"
        ? "Rodzaj: dopisek pacjenta"
        : sessionSeq !== null
          ? `Rodzaj: naprawa sesji ${sessionSeq}`
          : `Rodzaj: naprawa przebiegu agenta ${agentRunId}`,
      kind === "addendum" ? "Czas (deklaruje panel): 7 dni na rozpoczęcie dopisku" : "Czas (deklaruje panel): 1 h",
      "Panel prosi o przekazanie serwerowi klucza tego jednego wywiadu.",
    ],
    confirm: "Zatwierdź",
    cancel: "Odrzuć",
  }),
};
