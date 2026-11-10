import { generateJiraDemoKey } from "./demo-keygen.js";

export function setupDemoKeygen({ copyText, notify, library, state }) {
  const $ = id => document.getElementById(id);
  const tab = $("tab-demo-keygen"), panel = $("demo-keygen-view");
  const form = $("demo-keygen-form"), result = $("demo-keygen-result");
  const button = $("demo-generate"), output = $("demo-key-output");
  let active = false;
  function hide() {
    active = false;
    panel.hidden = true;
    tab.classList.remove("active");
    tab.setAttribute("aria-selected", "false");
  }
  function show() {
    library.switchTo("buffer");
    active = true;
    panel.hidden = false;
    $("composer").hidden = true;
    $("list").hidden = true;
    tab.classList.add("active");
    tab.setAttribute("aria-selected", "true");
    $("tab-buffer").classList.remove("active");
    $("tab-buffer").setAttribute("aria-selected", "false");
    $("count").textContent = "Генератор ключей · DEMO";
    $("search").setAttribute("aria-controls", "demo-keygen-view");
  }
  tab.addEventListener("click", show);
  form.addEventListener("submit", async e => {
    e.preventDefault();
    button.disabled = true;
    result.hidden = true;
    try {
      const fields = {
        serverId: $("demo-server-id").value.trim(),
        email: $("demo-email").value.trim(),
        organisation: $("demo-organisation").value.trim(),
        product: $("demo-product").value.trim(),
        name: $("demo-name").value.trim(),
        datacenter: $("demo-datacenter").checked
      };
      const generated = await generateJiraDemoKey(fields);
      output.value = generated.key;
      $("demo-properties-output").textContent = generated.properties;
      result.hidden = false;
      notify("Демонстрационный ключ сгенерирован локально");
    } catch (error) {
      notify("Ошибка генерации: " + error.message);
      console.error("DEMO key generator:", error);
    } finally { button.disabled = false; }
  });
  $("demo-copy").addEventListener("click", async () => {
    if (await copyText(output.value)) notify("Демонстрационный ключ скопирован");
    else notify("Не удалось скопировать ключ");
  });
  return { hide, isActive: () => active };
}
