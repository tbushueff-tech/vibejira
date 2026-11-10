// Jira Helper V2 — compatible with the existing AES-GCM v2 envelope and
// PBKDF2 crypto bundle. No plaintext clipboard is sent to Cloudflare.
const enc = new TextEncoder(), dec = new TextDecoder();
const DB_NAME = "vibejira_session", DB_STORE = "keys";
const DEFAULT_ITERATIONS = 600000;
export const OLD_CACHE_KEY = "bufer-tekstov-v1";

export function toBase64(bytes) {
  let out = "";
  for (let i = 0; i < bytes.length; i += 8192)
    out += String.fromCharCode(...bytes.subarray(i, i + 8192));
  return btoa(out);
}
export function fromBase64(value) {
  const raw = atob(value);
  return Uint8Array.from(raw, c => c.charCodeAt(0));
}
async function wrapKey(password, salt, iterations) {
  const base = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations, hash: "SHA-256" }, base,
    { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]
  );
}
async function importMaster(raw) {
  return crypto.subtle.importKey("raw", raw, { name: "AES-GCM" }, true, ["encrypt", "decrypt"]);
}
async function makeBundle(raw, password, iterations = DEFAULT_ITERATIONS) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const wrap = await wrapKey(password, salt, iterations);
  const wrapped = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, wrap, raw));
  return { v: 1, alg: "AES-256-GCM", kdf: "PBKDF2-SHA-256", iterations,
    salt: toBase64(salt), iv: toBase64(iv), wrappedKey: toBase64(wrapped) };
}
async function masterBytes(bundle, password) {
  if (!bundle || bundle.v !== 1 || !bundle.salt || !bundle.iv || !bundle.wrappedKey)
    throw new Error("Настройки шифрования аккаунта отсутствуют");
  const wrapping = await wrapKey(password, fromBase64(bundle.salt), Number(bundle.iterations) || DEFAULT_ITERATIONS);
  return crypto.subtle.decrypt({ name: "AES-GCM", iv: fromBase64(bundle.iv) }, wrapping, fromBase64(bundle.wrappedKey));
}
export async function createEncryption(password) {
  const raw = crypto.getRandomValues(new Uint8Array(32));
  return { key: await importMaster(raw), bundle: await makeBundle(raw, password) };
}
export async function unlockEncryption(bundle, password) {
  return importMaster(await masterBytes(bundle, password));
}
export async function rotateEncryption(bundle, currentPassword, nextPassword) {
  const raw = await masterBytes(bundle, currentPassword);
  return { key: await importMaster(raw), bundle: await makeBundle(raw, nextPassword) };
}
export async function encryptBuffer(items, key) {
  if (!key) throw new Error("Шифрование не разблокировано");
  const entries = [];
  for (const item of items) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const raw = enc.encode(JSON.stringify(item));
    const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, raw);
    entries.push({ v: 2, id: item.id, expiresAt: item.expiresAt,
      iv: toBase64(iv), ciphertext: toBase64(new Uint8Array(ciphertext)) });
  }
  return { v: 2, items: entries };
}
export async function decryptBuffer(envelope, key) {
  if (!key) throw new Error("Отсутствует ключ расшифровки");
  if (Array.isArray(envelope)) throw new Error("Незашифрованный облачный буфер требует отдельной миграции");
  if (!envelope || envelope.v !== 2 || !Array.isArray(envelope.items))
    throw new Error("Некорректный формат облачных данных");
  const result = [];
  for (const entry of envelope.items) {
    if (!entry || entry.v !== 2 || !entry.iv || !entry.ciphertext) throw new Error("Повреждённая запись");
    const raw = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: fromBase64(entry.iv) }, key, fromBase64(entry.ciphertext));
    const item = JSON.parse(dec.decode(raw));
    if (!item || typeof item !== "object") throw new Error("Неверная расшифрованная запись");
    if (!item.id) item.id = entry.id;
    if (!item.expiresAt) item.expiresAt = entry.expiresAt;
    result.push(item);
  }
  return result;
}
function dbOpen() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, 1);
    req.onupgradeneeded = () => {
      if (!req.result.objectStoreNames.contains(DB_STORE)) req.result.createObjectStore(DB_STORE);
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error || Error("IndexedDB unavailable"));
  });
}
async function transact(type, username, value) {
  const db = await dbOpen();
  try {
    return await new Promise((resolve, reject) => {
      const tx = db.transaction(DB_STORE, type === "get" ? "readonly" : "readwrite");
      const store = tx.objectStore(DB_STORE);
      const req = type === "get" ? store.get(username)
        : type === "put" ? store.put(value, username) : store.delete(username);
      req.onsuccess = () => resolve(req.result ?? null);
      req.onerror = () => reject(req.error);
      tx.onerror = () => reject(tx.error);
    });
  } finally { db.close(); }
}
export async function restoreKey(username) {
  const scoped = await transact("get", "account:" + username.toLowerCase());
  if (scoped) return scoped;
  // The original app saved a single unscoped key. Use it only as a candidate:
  // the caller must verify it by decrypting the user's cloud/local buffer.
  return transact("get", "encryption");
}
export async function rememberKey(username, key) {
  return transact("put", "account:" + username.toLowerCase(), key);
}
export async function forgetKey(username) {
  return transact("delete", "account:" + username.toLowerCase());
}
export function cacheKey(username) { return "vibejira-v2-cache:" + username.toLowerCase(); }
export async function readCache(username, key) {
  const raw = localStorage.getItem(cacheKey(username)) ||
    localStorage.getItem(OLD_CACHE_KEY);
  if (!raw) return null;
  const envelope = JSON.parse(raw);
  if (!envelope || envelope.v !== 2) return null;
  return decryptBuffer(envelope, key);
}
export async function writeCache(username, items, key) {
  const envelope = await encryptBuffer(items, key);
  localStorage.setItem(cacheKey(username), JSON.stringify(envelope));
}
export function clearScopedCache(username) {
  localStorage.removeItem(cacheKey(username)); // never delete the legacy backup
}
