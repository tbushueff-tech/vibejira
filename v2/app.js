import { CloudApi } from "./api.js";
import {
  createEncryption, unlockEncryption, rotateEncryption, encryptBuffer,
  decryptBuffer, restoreKey, rememberKey, forgetKey, readCache, writeCache,
  clearScopedCache
} from "./crypto.js";
import { createLibrary } from "./library.js";

// Jira Helper V2. No framework, keeps the existing HTML/CSS and element IDs.
// The UI never treats a partial remote download as a valid cloud snapshot.
const $ = id => document.getElementById(id);
const PROXY_MODE_KEY = "helper-use-russian-proxy";
const api = new CloudApi({ useProxy: localStorage.getItem(PROXY_MODE_KEY) === "1" });
const WEEK = 7 * 86400000, FIVE_MINUTES = 300000;
const TOKEN_KEY = "buffer_auth_token";
const state = {
  mode: "login", username: "", token: localStorage.getItem(TOKEN_KEY) || "",
  key: null, bundle: null, revision: null, profile: null, items: [], hydrated: false,
  busy: false, syncing: false, generation: 0, writeTimer: null, saveQueue: Promise.resolve(),
  query: "", currentSearch: 0, editing: null, register: false, deleteArmed: new Map(),
  avatarDraft: null
};
api.setToken(state.token);
const view = {
  login: $("login-screen"), loginForm: $("login-form"), loginUser: $("login-user"),
  loginPassword: $("login-password"), loginButton: $("login-button"), loginError: $("login-error"),
  proxyMode: $("login-russian-proxy"),
  registerToggle: $("register-toggle"), description: $("auth-description"),
  app: $("app"), status: $("sync-status"), list: $("list"), count: $("count"),
  search: $("search"), searchToggle: $("search-toggle"), searchPrev: $("search-prev"),
  searchNext: $("search-next"), searchPosition: $("search-position"),
  composer: $("composer"), title: $("title"), body: $("body"), save: $("save"),
  cancel: $("cancel"), liveCount: $("live-count"), accountButton: $("account-button"),
  dropdown: $("account-dropdown"), avatar: $("account-avatar"), authUser: $("auth-user"),
  accountMode: $("account-mode-label"), profileButton: $("edit-profile"),
  changePasswordButton: $("change-password"), accountLogin: $("account-login"),
  logout: $("logout"), profileModal: $("profile-modal"), profileForm: $("profile-form"),
  profileName: $("profile-name"), profileAvatar: $("profile-avatar-preview"),
  profileFile: $("profile-avatar-file"), profileRemove: $("profile-avatar-remove"),
  profileError: $("profile-error"), profileSubmit: $("profile-submit"),
  passwordModal: $("password-modal"), passwordForm: $("password-form"),
  passwordError: $("password-error"), passwordSubmit: $("password-submit"),
  toast: $("toast"), guestDisclaimer: $("guest-disclaimer")
};
const library = createLibrary({
  api,
  session: () => state,
  notify: message => notify(message),
  copyText: text => copyText(text),
  onTabChange: () => {
    state.query = view.search.value.trim();
    render();
  }
});

const expiry = item => Number(item.expiresAt) || 0;
const active = item => !expiry(item) || expiry(item) > Date.now();
const plural = (n, one, few, many) => {
  const x = Math.abs(n) % 100, y = x % 10;
  return x >= 11 && x <= 14 ? many : y === 1 ? one : y >= 2 && y <= 4 ? few : many;
};
const el = (tag, className, text) => {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
};
function notify(message) {
  view.toast.textContent = message;
  view.toast.classList.add("show");
  clearTimeout(notify.timer);
  notify.timer = setTimeout(() => view.toast.classList.remove("show"), 3500);
}
function setStatus(message) { view.status.textContent = message; }
function avatar(node, source, fallback) {
  node.replaceChildren();
  if (source && /^data:image\/(png|jpeg|webp);base64,/.test(source)) {
    const img = el("img"); img.alt = ""; img.src = source; node.append(img);
  } else node.textContent = String(fallback || "?").slice(0, 1).toUpperCase();
}
function setIdentity() {
  const display = state.profile?.displayName || state.username || "Гость";
  view.authUser.textContent = display;
  view.accountButton.setAttribute("aria-label", "Профиль: " + display);
  avatar(view.avatar, state.profile?.avatar, display);
  view.accountMode.textContent = state.mode === "guest" ? "Без регистрации · 5 минут" : "@" + state.username;
  view.profileButton.hidden = state.mode === "guest";
  view.changePasswordButton.hidden = state.mode === "guest";
  view.accountLogin.hidden = state.mode !== "guest";
  view.logout.hidden = state.mode === "guest";
}
function loginScreen(unlock = false) {
  state.mode = "login";
  view.app.classList.add("app-hidden");
  view.login.style.display = "flex";
  view.loginError.textContent = "";
  view.loginPassword.value = "";
  state.register = false;
  view.registerToggle.hidden = unlock;
  view.loginUser.readOnly = unlock;
  view.loginUser.value = unlock ? state.username : "";
  view.description.textContent = unlock
    ? "Сессия активна. Введите пароль, чтобы разблокировать зашифрованный буфер."
    : "Войдите или зарегистрируйтесь, чтобы сохранять буфер между устройствами.";
  view.loginButton.textContent = unlock ? "Разблокировать" : "Войти";
}
function showApp(mode, username, profile) {
  state.mode = mode; state.username = username || ""; state.profile = profile || null;
  view.login.style.display = "none";
  view.app.classList.remove("app-hidden");
  setIdentity();
  render();
}
async function localDisplay(username, key) {
  if (!key) return;
  try {
    const cached = await readCache(username, key);
    if (cached) {
      state.items = cached.filter(active);
      render();
      setStatus("Локальная копия. Проверка облака…");
    }
  } catch (error) {
    console.warn("Encrypted local cache cannot be opened:", error);
  }
}
async function afterLogin(data, key, bundle) {
  state.key = key; state.bundle = bundle; state.revision = null;
  if (bundle) localStorage.setItem("vibejira-v2-bundle:" + data.username.toLowerCase(), JSON.stringify(bundle));
  state.token = data.token; api.setToken(data.token);
  localStorage.setItem(TOKEN_KEY, data.token);
  library.reset();
  showApp("account", data.username, data.profile);
  await rememberKey(data.username, key).catch(error => console.warn("Key storage:", error));
  await localDisplay(data.username, key);
  await refreshCloud();
}
async function refreshCloud() {
  if (state.mode !== "account" || state.syncing || !state.key) return;
  const generation = state.generation;
  state.syncing = true;
  state.hydrated = false;
  setStatus("Загрузка облака небольшими частями…");
  try {
    const { envelope, revision } = await api.readBuffer({
      onProgress(done, total) {
        if (generation === state.generation)
          setStatus("Облако: " + Math.round(100 * done / (total || 1)) + "% (" + Math.round(done / 1024) + " КБ)");
      }
    });
    if (generation !== state.generation) return;
    const incoming = await decryptBuffer(envelope, state.key);
    if (generation !== state.generation) return;
    if (state.items.length > 0 && incoming.length < state.items.length) {
      // A shorter remote snapshot may be stale, or contain deletes from
      // another device. Never erase the local cache without reconciliation.
      throw new Error("Облако содержит меньше записей, чем локальная копия. Записи сохранены; запись заблокирована.");
    }
    state.revision = revision;
    state.items = incoming.filter(active);
    state.hydrated = true;
    render();
    setStatus("Синхронизировано через Cloudflare");
    await writeCache(state.username, state.items, state.key).catch(error => console.warn("Cache update:", error));
  } catch (error) {
    if (generation !== state.generation) return;
    state.hydrated = false;
    setStatus("Облако недоступно: " + error.message + " · локальная копия только для чтения");
    console.error("Cloud sync:", error);
  } finally {
    state.syncing = false;
  }
}
function editable() {
  if (state.mode === "guest") return true;
  if (state.mode === "account" && state.hydrated && !state.busy && !state.syncing) return true;
  notify("Дождитесь полной загрузки облака. Локальные данные защищены от перезаписи.");
  return false;
}
function scheduleWrite() {
  if (state.mode === "guest") { setStatus("Гостевой режим · данные не сохраняются"); return; }
  if (!state.hydrated) { setStatus("Запись заблокирована до полной загрузки"); return; }
  clearTimeout(state.writeTimer);
  state.busy = true;
  setStatus("Подготовка зашифрованного сохранения…");
  state.writeTimer = setTimeout(() => {
    // Explicit serialization of writes: never overlap POSTs for one account.
    state.saveQueue = state.saveQueue.catch(() => {}).then(async () => {
      const username = state.username;
      const generation = state.generation;
      const envelope = await encryptBuffer(state.items, state.key);
      await writeCache(username, state.items, state.key);
      const result = await api.writeBuffer(envelope, state.revision);
      if (generation === state.generation) {
        if (result.revision) state.revision = result.revision;
        else {
          // Original Worker does not return a revision. Stop further writes
          // until an authoritative post-write read verifies the new state.
          state.hydrated = false;
        }
        state.busy = false;
        setStatus(result.revision ? "Синхронизировано через Cloudflare" : "Запись отправлена · проверка облака…");
        if (!result.revision) await refreshCloud();
      }
    }).catch(error => {
      state.busy = false;
      state.hydrated = false; // prevents stale snapshots from subsequent writes
      setStatus("Ошибка записи: " + error.message + " · изменения сохранены локально");
      console.error("Cloud write:", error);
    });
  }, 650);
}
function mutate(action) {
  if (!editable()) return;
  action();
  state.items = state.items.filter(active);
  render();
  if (state.mode === "account") {
    writeCache(state.username, state.items, state.key).catch(console.error);
  }
  scheduleWrite();
}
function timeLeft(ms) {
  const seconds = Math.max(0, Math.ceil(ms / 1000));
  if (seconds >= 86400) return Math.ceil(seconds / 86400) + " дн.";
  if (seconds >= 3600) return Math.ceil(seconds / 3600) + " ч.";
  if (seconds >= 60) return Math.ceil(seconds / 60) + " мин.";
  return seconds + " сек.";
}
function highlight(node, text) {
  const word = state.query.trim();
  if (!word) { node.textContent = text || ""; return; }
  const source = String(text || "");
  const at = source.toLocaleLowerCase().indexOf(word.toLocaleLowerCase());
  if (at < 0) { node.textContent = source; return; }
  node.append(document.createTextNode(source.slice(0, at)));
  node.append(el("mark", "", source.slice(at, at + word.length)));
  node.append(document.createTextNode(source.slice(at + word.length)));
}
function seemsCode(text) {
  return /(?:^|\n)\s*(?:const |let |var |function |class |import |def |SELECT |INSERT |curl |\{\s*")/m.test(text) ||
    /[{};]/.test(text.slice(0, 1200));
}
function googleAi(text) {
  const url = "https://www.google.com/search?udm=50&q=" + encodeURIComponent(text.slice(0, 1700));
  window.open(url, "_blank", "noopener,noreferrer");
}
function copyFallback(text) {
  const area = el("textarea"); area.value = text;
  area.style.position = "fixed"; area.style.opacity = "0";
  document.body.append(area); area.select();
  const done = document.execCommand("copy"); area.remove(); return done;
}
async function copyText(text) {
  try { await navigator.clipboard.writeText(text); return true; }
  catch { try { return copyFallback(text); } catch { return false; } }
}
function startEdit(item) {
  if (!editable()) return;
  state.editing = item.id;
  view.title.value = item.title || "";
  view.body.value = item.text;
  $("composer-title").textContent = "Редактирование текста";
  view.save.textContent = "Сохранить";
  view.cancel.hidden = false;
  updateCount();
  view.title.focus();
  view.composer.scrollIntoView({ behavior: "smooth", block: "start" });
}
function stopEdit() {
  state.editing = null;
  view.composer.reset();
  $("composer-title").textContent = "Новый текст";
  view.save.textContent = "Сохранить";
  view.cancel.hidden = true;
  updateCount();
}
function card(item) {
  const node = el("article", "card");
  const head = el("div", "card-head");
  const title = el("h3", "card-title"); highlight(title, item.title || "Без названия");
  head.append(title);
  if (item.example) head.append(el("span", "badge", "пример"));
  if (expiry(item)) {
    const counter = el("span", "expiry", "⏱ " + timeLeft(expiry(item) - Date.now()));
    counter.dataset.expiresAt = String(expiry(item)); head.append(counter);
  }
  node.append(head);
  const snippet = el("pre", "snippet"); highlight(snippet, item.text || ""); node.append(snippet);
  if (item.text?.length > 260 || item.text?.split("\n").length > 6) {
    const more = el("button", "more", "Показать полностью"); more.type = "button";
    more.addEventListener("click", () => {
      const opened = snippet.classList.toggle("open");
      more.textContent = opened ? "Свернуть" : "Показать полностью";
    }); node.append(more);
  }
  const meta = el("div", "meta", (item.copies || 0) + " " + plural(item.copies || 0, "копирование", "копирования", "копирований"));
  node.append(meta);
  const actions = el("div", "actions");
  const copy = el("button", "primary copy", "Копировать"); copy.type = "button";
  copy.addEventListener("click", async () => {
    if (!await copyText(item.text)) { notify("Не удалось скопировать текст"); return; }
    notify("Текст скопирован");
    copy.textContent = "Скопировано"; copy.classList.add("done");
    setTimeout(() => { copy.textContent = "Копировать"; copy.classList.remove("done"); }, 1500);
    if (editable()) mutate(() => { item.copies = (item.copies || 0) + 1; });
  }); actions.append(copy);
  if (state.mode === "account") {
    const send = el("button", "ghost", "☆ В библиотеку");
    send.type = "button";
    send.title = "Сохранить код навсегда, отдельно от временного буфера";
    send.addEventListener("click", () => library.sendFromBuffer(item));
    actions.append(send);
  }
  if (seemsCode(item.text || "")) {
    const google = el("button", "google-ai-action", "✦ В Google AI");
    google.type = "button"; google.addEventListener("click", () => googleAi(item.text)); actions.append(google);
  }
  const edit = el("button", "ghost", "Изменить"); edit.type = "button";
  edit.addEventListener("click", () => startEdit(item)); actions.append(edit);
  const armed = (state.deleteArmed.get(item.id) || 0) > Date.now();
  const remove = el("button", "ghost danger", armed ? "Удалить насовсем?" : "Удалить");
  remove.type = "button";
  if (armed) remove.classList.add("armed");
  remove.addEventListener("click", () => {
    if (!editable()) return;
    if ((state.deleteArmed.get(item.id) || 0) < Date.now()) {
      state.deleteArmed.set(item.id, Date.now() + 8000);
      remove.textContent = "Удалить насовсем?"; remove.classList.add("armed"); return;
    }
    state.deleteArmed.delete(item.id);
    if (state.editing === item.id) stopEdit();
    mutate(() => { state.items = state.items.filter(x => x.id !== item.id); });
  }); actions.append(remove);
  node.append(actions);
  return node;
}
function render() {
  if (library.isActive()) {
    library.render(state.query);
    return;
  }
  const shown = state.items.filter(item => {
    const word = state.query.toLocaleLowerCase();
    return !word || (item.title || "").toLocaleLowerCase().includes(word) ||
      (item.text || "").toLocaleLowerCase().includes(word);
  });
  view.list.replaceChildren(...shown.map(card));
  if (!shown.length) {
    view.list.append(el("div", "empty", state.items.length
      ? "Ничего не найдено. Попробуйте другое слово."
      : "Здесь пока пусто. Добавьте первый текст в форме выше."));
  }
  view.count.textContent = state.query
    ? "Найдено " + shown.length + " из " + state.items.length
    : state.items.length + " " + plural(state.items.length, "текст", "текста", "текстов");
  if (view.searchPosition) view.searchPosition.textContent = shown.length
    ? Math.min(state.currentSearch + 1, shown.length) + " / " + shown.length : "0 / 0";
}
function updateCount() {
  const text = view.body.value.trim();
  view.liveCount.textContent = text.length + " симв. · " + (text ? text.split(/\s+/).length : 0) + " слов";
}
function changeSearch(delta) {
  const scope = library.isActive() ? $("library-list") : view.list;
  const matches = [...scope.querySelectorAll("mark")];
  if (!matches.length) return;
  state.currentSearch = (state.currentSearch + delta + matches.length) % matches.length;
  matches[state.currentSearch].scrollIntoView({ behavior: "smooth", block: "center" });
  view.searchPosition.textContent = (state.currentSearch + 1) + " / " + matches.length;
}
function previewAvatar() {
  avatar(view.profileAvatar, state.avatarDraft,
    view.profileName.value || state.username);
}
async function fileAvatar(file) {
  if (!file || !/^image\/(png|jpeg|webp)$/.test(file.type) || file.size > 5 * 1024 * 1024)
    throw new Error("Выберите PNG, JPG или WebP до 5 МБ");
  const url = URL.createObjectURL(file), image = new Image();
  try {
    await new Promise((resolve, reject) => {
      image.onload = resolve; image.onerror = reject; image.src = url;
    });
    const canvas = document.createElement("canvas");
    canvas.width = canvas.height = 160;
    const side = Math.min(image.naturalWidth, image.naturalHeight);
    canvas.getContext("2d").drawImage(image, (image.naturalWidth - side) / 2,
      (image.naturalHeight - side) / 2, side, side, 0, 0, 160, 160);
    const data = canvas.toDataURL("image/jpeg", 0.78);
    if (data.length > 90000) throw new Error("Изображение слишком большое");
    return data;
  } finally { URL.revokeObjectURL(url); }
}
async function logout() {
  clearTimeout(state.writeTimer);
  await state.saveQueue.catch(() => {});
  const username = state.username;
  try { await api.logout(); } catch (error) { console.warn("Logout:", error); }
  state.generation++; state.token = ""; state.key = null; state.bundle = null;
  state.profile = null; state.items = []; state.hydrated = false; state.revision = null; state.username = "";
  library.reset();
  api.setToken("");
  localStorage.removeItem(TOKEN_KEY);
  if (username) await forgetKey(username).catch(console.warn);
  if (username) clearScopedCache(username);
  loginScreen();
}
function bind() {
  view.proxyMode.checked = api.useProxy;
  view.proxyMode.addEventListener("change", () => {
    api.setProxyMode(view.proxyMode.checked);
    localStorage.setItem(PROXY_MODE_KEY, api.useProxy ? "1" : "0");
    view.loginError.textContent = "";
  });
  view.loginForm.addEventListener("submit", async event => {
    event.preventDefault();
    const username = view.loginUser.value.trim(), password = view.loginPassword.value;
    view.loginError.textContent = "";
    if (username.length < 3 || password.length < 6) {
      view.loginError.textContent = "Логин от 3 символов, пароль от 6"; return;
    }
    view.loginButton.disabled = true;
    try {
      let data, key, bundle;
      if (state.register) {
        const created = await createEncryption(password);
        bundle = created.bundle; key = created.key;
        data = await api.register(username, password, bundle);
      } else {
        data = await api.login(username, password);
        if (data.crypto) {
          bundle = data.crypto; key = await unlockEncryption(data.crypto, password);
        } else {
          const created = await createEncryption(password);
          bundle = created.bundle; key = created.key;
          api.setToken(data.token);
          await api.saveCrypto(bundle);
        }
      }
      state.generation++;
      await afterLogin(data, key, bundle);
    } catch (error) {
      view.loginError.textContent = error.message || "Не удалось войти";
    } finally {
      view.loginButton.disabled = false;
      view.loginButton.textContent = state.register ? "Зарегистрироваться" : "Войти";
    }
  });
  view.registerToggle.addEventListener("click", () => {
    state.register = !state.register;
    view.loginButton.textContent = state.register ? "Зарегистрироваться" : "Войти";
    view.registerToggle.textContent = state.register ? "У меня уже есть аккаунт" : "Регистрация";
    view.loginError.textContent = "";
  });
  $("guest-mode").addEventListener("click", () => { view.guestDisclaimer.hidden = false; });
  $("guest-cancel").addEventListener("click", () => { view.guestDisclaimer.hidden = true; });
  $("guest-confirm").addEventListener("click", () => {
    view.guestDisclaimer.hidden = true; state.generation++; state.items = []; state.hydrated = true;
    library.reset();
    showApp("guest"); setStatus("Гостевой режим · данные не сохраняются");
  });
  view.guestDisclaimer.addEventListener("click", e => {
    if (e.target === view.guestDisclaimer) view.guestDisclaimer.hidden = true;
  });
  view.composer.addEventListener("submit", event => {
    event.preventDefault();
    const text = view.body.value.trimEnd(), title = view.title.value.trim();
    if (!text.trim()) return notify("Введите текст");
    if (!editable()) return;
    mutate(() => {
      if (state.editing) {
        const target = state.items.find(item => item.id === state.editing);
        if (target) { target.title = title; target.text = text; }
      } else {
        state.items.unshift({ id: crypto.randomUUID(), title, text, copies: 0,
          expiresAt: Date.now() + (state.mode === "guest" ? FIVE_MINUTES : WEEK) });
      }
    });
    stopEdit();
  });
  view.cancel.addEventListener("click", stopEdit);
  view.body.addEventListener("input", updateCount);
  view.body.addEventListener("keydown", event => {
    if ((event.ctrlKey || event.metaKey) && event.key === "Enter") {
      event.preventDefault(); view.composer.requestSubmit();
    }
  });
  $("composer-google-ai").addEventListener("click", () => googleAi(view.body.value));
  view.search.addEventListener("input", () => {
    state.query = view.search.value.trim(); state.currentSearch = 0;
    library.setSearch(state.query); render();
  });
  view.searchPrev.addEventListener("click", () => changeSearch(-1));
  view.searchNext.addEventListener("click", () => changeSearch(1));
  view.search.addEventListener("keydown", e => {
    if (e.key === "Escape") { view.search.value = ""; state.query = ""; render(); }
    if (e.key === "ArrowDown" || e.key === "Enter") { e.preventDefault(); changeSearch(1); }
    if (e.key === "ArrowUp") { e.preventDefault(); changeSearch(-1); }
  });
  view.searchToggle.addEventListener("click", () => {
    const header = view.app.querySelector("header");
    const open = !header.classList.contains("search-open");
    header.classList.toggle("search-open", open);
    if (open) view.search.focus();
    else { view.search.value = ""; state.query = ""; render(); }
  });
  view.accountButton.addEventListener("click", async () => {
    view.dropdown.hidden = !view.dropdown.hidden;
    if (!view.dropdown.hidden && state.mode === "account") {
      try { const response = await api.me(); state.profile = response.profile; setIdentity(); }
      catch (error) { console.warn("Profile refresh:", error); }
    }
  });
  document.addEventListener("click", event => {
    if (!event.target.closest(".account-menu")) view.dropdown.hidden = true;
  });
  view.accountLogin.addEventListener("click", () => { view.dropdown.hidden = true; loginScreen(); });
  view.logout.addEventListener("click", logout);
  view.profileButton.addEventListener("click", () => {
    view.dropdown.hidden = true; view.profileError.textContent = "";
    view.profileName.value = state.profile?.displayName || state.username;
    state.avatarDraft = state.profile?.avatar || null;
    previewAvatar(); view.profileModal.hidden = false;
  });
  $("profile-close").addEventListener("click", () => { view.profileModal.hidden = true; });
  view.profileModal.addEventListener("click", e => {
    if (e.target === view.profileModal) view.profileModal.hidden = true;
  });
  view.profileName.addEventListener("input", previewAvatar);
  view.profileRemove.addEventListener("click", () => { state.avatarDraft = null; previewAvatar(); });
  view.profileFile.addEventListener("change", async () => {
    try { state.avatarDraft = await fileAvatar(view.profileFile.files[0]); previewAvatar(); }
    catch (error) { view.profileError.textContent = error.message; }
  });
  view.profileForm.addEventListener("submit", async event => {
    event.preventDefault();
    const displayName = view.profileName.value.trim();
    if (!displayName || displayName.length > 40) {
      view.profileError.textContent = "Имя должно содержать 1–40 символов"; return;
    }
    view.profileSubmit.disabled = true;
    try {
      const response = await api.saveProfile(displayName, state.avatarDraft);
      state.profile = response.profile;
      setIdentity(); view.profileModal.hidden = true; notify("Профиль сохранён");
    } catch (error) { view.profileError.textContent = error.message; }
    finally { view.profileSubmit.disabled = false; }
  });
  view.changePasswordButton.addEventListener("click", () => {
    view.dropdown.hidden = true; view.passwordError.textContent = "";
    view.passwordForm.reset(); view.passwordModal.hidden = false;
  });
  $("password-close").addEventListener("click", () => { view.passwordModal.hidden = true; });
  view.passwordModal.addEventListener("click", e => {
    if (e.target === view.passwordModal) view.passwordModal.hidden = true;
  });
  view.passwordForm.addEventListener("submit", async event => {
    event.preventDefault();
    const current = $("current-password").value, next = $("new-password").value;
    if (next.length < 6 || next !== $("new-password-2").value) {
      view.passwordError.textContent = "Пароль от 6 символов, повтор должен совпадать"; return;
    }
    view.passwordSubmit.disabled = true;
    try {
      const rotated = await rotateEncryption(state.bundle, current, next);
      await api.changePassword(current, next, rotated.bundle);
      state.key = rotated.key; state.bundle = rotated.bundle;
      localStorage.setItem("vibejira-v2-bundle:" + state.username.toLowerCase(), JSON.stringify(rotated.bundle));
      await rememberKey(state.username, state.key);
      view.passwordModal.hidden = true; notify("Пароль изменён");
    } catch (error) { view.passwordError.textContent = error.message; }
    finally { view.passwordSubmit.disabled = false; }
  });
  window.addEventListener("online", () => {
    if (state.mode === "account" && !state.hydrated) refreshCloud();
  });
  setInterval(() => {
    if (state.mode === "guest") {
      const before = state.items.length;
      state.items = state.items.filter(active);
      if (before !== state.items.length) render();
    }
    view.list.querySelectorAll(".expiry[data-expires-at]").forEach(node => {
      node.textContent = "⏱ " + timeLeft(Number(node.dataset.expiresAt) - Date.now());
    });
  }, 1000);
  setInterval(() => {
    if (state.mode === "account" && state.hydrated && !state.busy && !state.syncing) refreshCloud();
  }, 60000);
}
async function startup() {
  bind(); render(); updateCount();
  if (!state.token) { loginScreen(); return; }
  try {
    const session = await api.me();
    if (!session.authenticated) { loginScreen(); return; }
    state.username = session.username;
    const key = await restoreKey(session.username).catch(() => null);
    if (!key) { loginScreen(true); return; }
    state.key = key;
    state.bundle = session.crypto || null;
    state.generation++;
    library.reset();
    showApp("account", session.username, session.profile);
    await localDisplay(session.username, key);
    await refreshCloud();
  } catch (error) {
    console.warn("Session restore deferred:", error);
    // Network errors are NOT logout. A signed token remains in storage.
    loginScreen(!!state.username);
    view.loginError.textContent = "Не удалось восстановить подключение: " + error.message;
  }
}
startup();
