// D13: Chrome, Edge, Firefox. Safari (WebKit) blokowany — WebKit bug 311099
// zwraca zaszyfrowane wyjście hmac-secret jako PRF.

export function isWebKit(userAgent) {
  if (/iPhone|iPad|iPod/.test(userAgent)) return true; // na iOS każda przeglądarka to WebKit
  return /AppleWebKit/.test(userAgent) && !/Chrome|Chromium|Edg\//.test(userAgent);
}

export function browserOk(win) {
  if (isWebKit(win.navigator.userAgent)) return false;
  return typeof win.PublicKeyCredential === "function" && !!win.crypto?.subtle;
}
