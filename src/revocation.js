// Lista unieważnionych wersji sejfu, pobierana z własnego originu sejfu.

export function isRevoked(version, revokedDoc) {
  if (revokedDoc === null || typeof revokedDoc !== "object") return true;
  if (!Array.isArray(revokedDoc.revoked)) return true;
  return revokedDoc.revoked.includes(version);
}

// Brak listy albo błąd sieci = traktujemy jak unieważnioną (fail closed).
export async function fetchRevoked(fetchFn, url) {
  try {
    const res = await fetchFn(url, { cache: "no-store" });
    if (!res.ok) return null;
    return await res.json();
  } catch {
    return null;
  }
}
