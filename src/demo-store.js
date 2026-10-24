// Lista kluczy strony demo — wyłącznie w tej przeglądarce (localStorage).
// Sam YubiKey nie da się przejrzeć ze strony WWW; prawdziwa lista kluczy
// lekarza to DoctorKeyWrap w bobik-2.

const KEY = "bobik-sejf/demo/keys/v1";

export function createStore(storage) {
  let persistent = true;
  let memory = read();

  function read() {
    try {
      const raw = storage.getItem(KEY);
      if (raw === null) return [];
      const parsed = JSON.parse(raw);
      return Array.isArray(parsed) ? parsed : [];
    } catch (e) {
      if (!(e instanceof SyntaxError)) persistent = false;
      return [];
    }
  }

  function write() {
    try {
      storage.setItem(KEY, JSON.stringify(memory));
    } catch {
      persistent = false;
    }
  }

  return {
    list: () => memory.map((e) => ({ ...e })),
    add(entry) {
      memory = [...memory, { ...entry }];
      write();
    },
    remove(credentialId) {
      memory = memory.filter((e) => e.credentialId !== credentialId);
      write();
    },
    persistent: () => persistent,
  };
}
