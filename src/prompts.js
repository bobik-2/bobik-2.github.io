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
    lines: [`Lekarz: ${displayName}`, n === 1 ? "Włóż pierwszy klucz sprzętowy (YubiKey)." : "Wyjmij pierwszy klucz i włóż drugi (zapasowy).", TOUCH],
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
  createClinic: (label) => ({
    kind: "create_clinic",
    title: "Nowy klucz kliniki",
    lines: [`Zakładam klucz kliniki ${label}.`, "Klucz prywatny kliniki powstaje w sejfie i nie opuszcza go w postaci jawnej."],
    confirm: "Załóż klucz",
    cancel: "Anuluj",
  }),
  grantAccess: (label, fingerprint) => ({
    kind: "grant_access",
    title: "Nadanie dostępu do kliniki",
    // Odcisk (liczony w sejfie) zawsze w pierwszym wierszu, przed nieuwierzytelnioną etykietą (M-2).
    lines: [
      `Odcisk klucza odbiorcy: ${fingerprint}`,
      `Odbiorca — nazwa z panelu (niezweryfikowana): ${label}`,
      "Porównaj odcisk z tym, który odbiorca odczytał ze swojego sejfu — przez telefon albo osobiście, nie przez panel.",
    ],
    confirm: "Odcisk zgodny — nadaj dostęp",
    cancel: "Odcisk niezgodny — anuluj",
  }),
  grantLease: ({ kind, studyCode, sessionSeq, agentRunId }) => ({
    kind: "grant_lease",
    title: kind === "addendum" ? "Odblokowanie dopisku" : "Dzierżawa naprawcza",
    lines: [
      `Wywiad: ${studyCode}`,
      kind === "addendum"
        ? "Rodzaj: dopisek pacjenta"
        : sessionSeq !== null
          ? `Rodzaj: naprawa sesji ${sessionSeq}`
          : `Rodzaj: naprawa przebiegu agenta ${agentRunId}`,
      kind === "addendum" ? "Czas: 7 dni na rozpoczęcie dopisku" : "Czas: 1 h",
      "Serwer dostanie klucz tego jednego wywiadu na ten czas.",
    ],
    confirm: "Zatwierdź",
    cancel: "Odrzuć",
  }),
};
