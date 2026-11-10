import { encryptLibraryEntry, decryptLibraryEntry } from "./crypto.js";

const $ = id => document.getElementById(id);
const LANGS = [
  ["groovy", /(?:^|\n)\s*(?:import com\.atlassian|import groovy\.|def\s+\w+|@BaseScript)/m],
  ["sql", /(?:^|\n)\s*(?:SELECT|UPDATE|INSERT|DELETE|WITH)\s+/im],
  ["python", /(?:^|\n)\s*(?:def\s+\w+\(|from\s+\w+\s+import|import\s+\w+|class\s+\w+:)/m],
  ["json", /^\s*[\[{]/],
  ["javascript", /(?:\bconst\s+|\blet\s+|\bfunction\s+|=>|\bconsole\.)/],
  ["bash", /(?:^|\n)\s*(?:#!\/bin\/|curl\s|npm\s|sudo\s|git\s)/m],
  ["java", /(?:public\s+class|public\s+static\s+void)/],
];
const plain = (tag, cls, text) => {
  const node = document.createElement(tag);
  if (cls) node.className = cls;
  if (text !== undefined) node.textContent = text;
  return node;
};
const firstMatch = (text, fallback = "text") => LANGS.find(([, pattern]) => pattern.test(text))?.[0] || fallback;

export function createLibrary({ api, session, notify, copyText, onTabChange }) {
  const tabBuffer = $("tab-buffer");
  const tabLibrary = $("tab-library");
  const panel = $("library-view");
  const bufferForm = $("composer");
  const bufferList = $("list");
  const count = $("count");
  const status = $("library-status");
  const form = $("library-form");
  const list = $("library-list");
  const title = $("library-title");
  const language = $("library-language");
  const code = $("library-code");
  const notes = $("library-notes");
  const saveButton = $("library-save");
  const cancelButton = $("library-cancel");
  const heading = $("library-form-heading");

  let page = "buffer", entries = [], loadedFor = "", loading = false;
  let busy = false, editing = null, search = "", serial = 0;
  const armed = new Map();

  function current() {
    const s = session();
    return s.mode === "account" && !!s.key && !!s.token ? s : null;
  }
  function reset() {
    serial++;
    entries = []; loadedFor = ""; loading = false; busy = false;
    editing = null; search = ""; armed.clear(); cancelEdit();
    switchTo("buffer");
  }
  function switchTo(name) {
    if (name === "library" && !current()) {
      notify("Войдите в аккаунт, чтобы пользоваться постоянной библиотекой кода");
      return;
    }
    page = name;
    tabBuffer.classList.toggle("active", page === "buffer");
    tabLibrary.classList.toggle("active", page === "library");
    tabBuffer.setAttribute("aria-selected", String(page === "buffer"));
    tabLibrary.setAttribute("aria-selected", String(page === "library"));
    panel.hidden = page !== "library";
    bufferForm.hidden = page !== "buffer";
    bufferList.hidden = page !== "buffer";
    $("search").setAttribute("aria-controls", page === "library" ? "library-list" : "list");
    if (page === "library") {
      render();
      if (!loadedFor && !loading) refresh();
    }
    onTabChange?.();
  }
  function isActive() { return page === "library"; }
  function setSearch(text) { search = text.toLocaleLowerCase(); if (isActive()) render(); }
  function textContent(node, value) {
    const needle = search.trim();
    if (!needle) { node.textContent = String(value || ""); return; }
    const original = String(value || "");
    const at = original.toLocaleLowerCase().indexOf(needle);
    if (at < 0) { node.textContent = original; return; }
    node.append(document.createTextNode(original.slice(0, at)));
    node.append(plain("mark", "", original.slice(at, at + needle.length)));
    node.append(document.createTextNode(original.slice(at + needle.length)));
  }
  function cancelEdit() {
    editing = null;
    form.reset();
    heading.textContent = "Новый фрагмент кода";
    saveButton.textContent = "Сохранить в библиотеку";
    cancelButton.hidden = true;
  }
  async function refresh() {
    const s = current();
    if (!s || loading || busy) return;
    const activeSerial = serial;
    const username = s.username.toLowerCase();
    loading = true;
    status.textContent = "Загрузка постоянной библиотеки…";
    try {
      const encrypted = await api.listLibrary();
      const decoded = [];
      for (const item of encrypted) decoded.push(await decryptLibraryEntry(item, s.key));
      if (serial !== activeSerial || !current() || current().username.toLowerCase() !== username) return;
      entries = decoded.sort((a,b) => (b.updatedAt || 0) - (a.updatedAt || 0));
      loadedFor = username;
      status.textContent = "Библиотека синхронизирована · записи хранятся без срока удаления";
      if (isActive()) render();
    } catch (error) {
      status.textContent = "Ошибка загрузки библиотеки: " + error.message;
      console.error("Code library download:", error);
    } finally {
      loading = false;
    }
  }
  async function storeEntry(entry, revision = 0) {
    const s = current();
    if (!s || busy) throw new Error("Сначала войдите в аккаунт");
    const accountToken = s.token;
    busy = true;
    saveButton.disabled = true;
    try {
      const cipher = await encryptLibraryEntry(entry, s.key, revision);
      if (current()?.token !== accountToken) throw new Error("Аккаунт сменился во время сохранения");
      const result = await api.saveLibraryItem(cipher);
      if (current()?.token !== accountToken) throw new Error("Аккаунт сменился во время сохранения");
      const stored = { ...entry, revision: result.revision };
      const i = entries.findIndex(x => x.id === entry.id);
      if (i >= 0) entries[i] = stored;
      else entries.unshift(stored);
      entries.sort((a,b) => (b.updatedAt || 0) - (a.updatedAt || 0));
      loadedFor = s.username.toLowerCase();
      render();
      return stored;
    } finally {
      busy = false;
      saveButton.disabled = false;
    }
  }
  async function sendFromBuffer(item) {
    if (!current()) { notify("Постоянная библиотека доступна только после входа"); return; }
    if (busy || loading) { notify("Библиотека выполняет другую операцию"); return; }
    if (loadedFor !== current().username.toLowerCase()) await refresh();
    if (loadedFor !== current().username.toLowerCase()) {
      notify("Сначала необходимо загрузить библиотеку из облака"); return;
    }
    const duplicate = entries.find(x => x.sourceId === item.id);
    if (duplicate) { notify("Этот код уже есть в библиотеке"); switchTo("library"); return; }
    const now = Date.now();
    const entry = {
      id: crypto.randomUUID(), sourceId: item.id,
      title: (item.title || "Фрагмент кода").slice(0,120),
      text: item.text, language: firstMatch(item.text), notes: "",
      createdAt: now, updatedAt: now
    };
    try {
      await storeEntry(entry);
      notify("Код сохранён в постоянной библиотеке");
      switchTo("library");
    } catch (error) {
      notify("Не удалось сохранить код: " + error.message);
    }
  }
  function card(item) {
    const node = plain("article", "card");
    const head = plain("div", "card-head");
    const name = plain("h3", "card-title"); textContent(name, item.title || "Без названия");
    head.append(name, plain("span", "badge", item.language || "text"));
    node.append(head);
    if (item.notes) node.append(plain("div", "library-meta", item.notes));
    const snippet = plain("pre", "snippet library-code"); textContent(snippet, item.text);
    node.append(snippet);
    if (item.text?.length > 260 || item.text?.split("\n").length > 6) {
      const more = plain("button", "more", "Показать полностью");
      more.type = "button";
      more.addEventListener("click", () => {
        const open = snippet.classList.toggle("open");
        more.textContent = open ? "Свернуть" : "Показать полностью";
      });
      node.append(more);
    }
    if (item.updatedAt) {
      node.append(plain("div", "library-meta",
        "Обновлено: " + new Date(item.updatedAt).toLocaleString("ru-RU")));
    }
    const actions = plain("div", "actions");
    const copy = plain("button", "primary copy", "Копировать"); copy.type = "button";
    copy.addEventListener("click", async () => {
      if (await copyText(item.text)) notify("Код скопирован");
      else notify("Не удалось скопировать код");
    });
    actions.append(copy);
    const edit = plain("button", "ghost", "Изменить"); edit.type = "button";
    edit.addEventListener("click", () => {
      editing = item.id;
      title.value = item.title || ""; language.value = item.language || "text";
      code.value = item.text || ""; notes.value = item.notes || "";
      heading.textContent = "Редактирование фрагмента кода";
      saveButton.textContent = "Сохранить изменения";
      cancelButton.hidden = false;
      form.scrollIntoView({ behavior:"smooth", block:"start" });
      title.focus();
    });
    actions.append(edit);
    const del = plain("button", "ghost danger", "Удалить"); del.type = "button";
    del.addEventListener("click", async () => {
      if (busy) return;
      if ((armed.get(item.id) || 0) < Date.now()) {
        armed.set(item.id, Date.now() + 8000);
        del.textContent = "Удалить насовсем?";
        del.classList.add("armed");
        return;
      }
      armed.delete(item.id);
      busy = true; del.disabled = true;
      try {
        await api.deleteLibraryItem(item.id, item.revision);
        entries = entries.filter(x => x.id !== item.id);
        if (editing === item.id) cancelEdit();
        notify("Код удалён из библиотеки");
        render();
      } catch (error) {
        notify("Ошибка удаления: " + error.message);
        del.disabled = false;
      } finally {
        busy = false;
      }
    });
    actions.append(del);
    node.append(actions);
    return node;
  }
  function render(query) {
    if (query !== undefined) search = query.toLocaleLowerCase();
    if (!isActive()) return;
    const filtered = entries.filter(x => !search ||
      [x.title, x.text, x.notes, x.language].some(y => (y || "").toLocaleLowerCase().includes(search)));
    list.replaceChildren(...filtered.map(card));
    if (!filtered.length) list.append(plain("div", "empty", loading
      ? "Загрузка библиотеки…" :
      !entries.length ? "В библиотеке пока пусто. Отправьте сюда проверенный код из буфера." :
      "По вашему запросу ничего не найдено."));
    count.textContent = search ? "Найдено " + filtered.length + " из " + entries.length :
      entries.length + " " + (entries.length === 1 ? "фрагмент" : "фрагментов") + " в библиотеке";
    return filtered.length;
  }
  async function onSubmit(event) {
    event.preventDefault();
    const s = current();
    if (!s) { notify("Войдите для сохранения кода"); return; }
    if (loadedFor !== s.username.toLowerCase()) await refresh();
    if (loadedFor !== s.username.toLowerCase()) {
      notify("Не удалось проверить содержимое библиотеки"); return;
    }
    if (busy) return;
    const now = Date.now();
    const original = editing ? entries.find(x => x.id === editing) : null;
    if (editing && !original) { notify("Запись не найдена. Обновите библиотеку."); return; }
    const entry = {
      id: original?.id || crypto.randomUUID(),
      sourceId: original?.sourceId || null,
      title: title.value.trim().slice(0,120),
      language: language.value, text: code.value,
      notes: notes.value.trim(),
      createdAt: original?.createdAt || now, updatedAt: now
    };
    if (!entry.title || !entry.text.trim()) { notify("Укажите название и код"); return; }
    try {
      await storeEntry(entry, original?.revision || 0);
      cancelEdit(); notify("Код сохранён в постоянной библиотеке");
    } catch (error) { notify("Ошибка сохранения: " + error.message); }
  }

  tabBuffer.addEventListener("click", () => { $("search").value = ""; search = ""; switchTo("buffer"); });
  tabLibrary.addEventListener("click", () => {
    $("search").value = ""; search = ""; switchTo("library");
  });
  $("library-refresh").addEventListener("click", () => refresh());
  form.addEventListener("submit", onSubmit);
  cancelButton.addEventListener("click", cancelEdit);

  return { reset, isActive, render, setSearch, sendFromBuffer, refresh, switchTo };
}
