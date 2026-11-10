// Demonstration-only transcription of Atlassian-Agent LicenseProperty semantics.
// Uses Jira Helper's own publicly embedded DSA key, not Atlassian-Agent's key.
// Structures and flags mirror reference v1.3.1, but the result is watermarked,
// independently signed, and NOT a real license or activation code.
import { javaPropertyEntries } from "./java-properties-order.js";
import { javaLocalDates } from "./java-local-date.js";

const productNames = {
  jira: "jira.product.jira-software",
  jc: "jira.product.jira-core",
  jsd: "jira.product.jira-servicedesk",
  jsm: "jira.product.jira-servicedesk",
  conf: "conf", questions: "com.atlassian.confluence.plugins.confluence-questions",
  tc: "team_calendars", bamboo: "bamboo", bitbucket: "stash",
  fisheye: "fisheye", crucible: "crucible", crowd: "crowd",
  capture: "bonfire", training: "atlassian-jira-training",
  portfolio: "com.radiantminds.roadmaps-jira",
};
const plugins = new Set(["questions", "tc", "capture", "training", "portfolio"]);
const expires = new Date(3771590399000);
export function escapeJavaProperty(str, isKey) {
  const s = String(str);
  let result = "";
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (c === "\t") result += "\\t";
    else if (c === "\n") result += "\\n";
    else if (c === "\f") result += "\\f";
    else if (c === "\r") result += "\\r";
    else if (c === " ") result += (i === 0 || isKey ? "\\" : "") + " ";
    else if (c === "\\") result += "\\\\";
    else result += ("=: \t\r\n\f#!".includes(c) ? "\\" : "") + c;
  }
  return result;
}
export function propertiesForDemoProduct({
  serverId, email, organisation, product = "jira", name, datacenter = false,
  now = new Date(), timeZone
} = {}) {
  if (!serverId?.trim() || !email?.trim() || !organisation?.trim() || !product?.trim())
    throw new Error("Укажите Server ID, email, организацию и продукт");
  const chosen = product.trim();
  if (!/^[a-zA-Z0-9_.-]{1,120}$/.test(chosen))
    throw new Error("Product: допустимы буквы A–Z, цифры, _, - и точка");
  const dt = new Date(now);
  if (Number.isNaN(dt.getTime())) throw new Error("Неверная дата генерации");
  const known = Object.hasOwn(productNames, chosen);
  const key = known ? productNames[chosen] : chosen;
  const plugin = plugins.has(chosen) || !known;
  const localDate = javaLocalDates(dt, timeZone);
  const expiryDate = javaLocalDates(expires, timeZone).dateOnly;
  const prefix = field => key + "." + field;
  const data = new Map();
  const put = (field, value) => data.set(field, value == null ? null : String(value));
  const active = "true", dc = Boolean(datacenter);
  // Mirrors LicenseProperty.init() and product subclasses' overrides.
  put(prefix("active"), active);
  if (chosen === "jira") { put("greenhopper.active", active); put("jira.active", active); }
  if (chosen === "jc") put("jira.active", active);
  if (chosen === "jsd" || chosen === "jsm") put("com.atlassian.servicedesk.active", active);
  put("PurchaseDate", localDate.dateOnly);
  put("LicenseExpiryDate", expiryDate);
  put("MaintenanceExpiryDate", expiryDate);
  if (chosen !== "bamboo") {
    if (!plugin) put(prefix("NumberOfUsers"), "-1");
    if (["jira", "jc"].includes(chosen)) put("jira.NumberOfUsers", "-1");
    if (plugin || ["jira","jc","jsd","jsm"].includes(chosen))
      put("NumberOfUsers", "-1");
  }
  put(prefix("Starter"), "false");
  const id = "L" + dt.getTime();
  put("SEN", "SEN-" + id);
  put("LicenseID", "LIDSEN-" + id);
  put("CreationDate", localDate.dateOnly);
  if (["jira", "jc"].includes(chosen)) {
    put("LicenseTypeName", "COMMERCIAL");
    if (chosen === "jira") put("greenhopper.LicenseTypeName", "COMMERCIAL");
    put("jira.LicenseTypeName", "COMMERCIAL");
  } else if (["jsd","jsm"].includes(chosen)) {
    put("LicenseTypeName", "COMMERCIAL");
    put("com.atlassian.servicedesk.LicenseTypeName", "COMMERCIAL");
  } else if (!known || chosen === "capture") {
    // ThirdPlugin, including Capture, overrides setLicenseType.
    put("LicenseTypeName", "COMMERCIAL");
  } else put(prefix("LicenseTypeName"), "COMMERCIAL");
  put("Description", "Unlimited license by https://zhile.io");
  put("Evaluation", "false");
  put("ContactName", name || email);
  put("ContactEMail", email);
  put("ServerID", serverId);
  put("Organisation", organisation);
  if (dc) {
    put(prefix("DataCenter"), "true");
    put("Subscription", "true");
    if (["jira", "jsd", "jsm"].includes(chosen)) put("jira.DataCenter", "true");
  }
  put("licenseVersion", "2");
  put("keyVersion", "1600708331");

  if (plugin) {
    put("LicenseID", null);
    put(prefix("enterprise"), "true");
  }
  if (chosen === "training") put("Subscription", "true");
  if (chosen === "jira") {
    put("greenhopper.LicenseEdition", "UNLIMITED");
    put("jira.LicenseEdition", "UNLIMITED");
    put("greenhopper.enterprise", "true");
  } else if (chosen === "jc") {
    put("jira.LicenseEdition", "UNLIMITED");
  } else if (["jsd", "jsm"].includes(chosen)) {
    put("com.atlassian.servicedesk.enterprise", "true");
    put("com.atlassian.servicedesk.numRoleCount", "-1");
  } else if (chosen === "bamboo") {
    put(prefix("LicenseEdition"), "UNLIMITED");
    put(prefix("NumberOfBambooLocalAgents"), "-1");
    put(prefix("NumberOfBambooRemoteAgents"), "1000");
    put(prefix("NumberOfBambooPlans"), "-1");
  }
  return { header: "#" + localDate.dateTime, data, key, isPlugin: plugin };
}
export function serializeForLicenseHash(data) {
  return [...data.entries()]
    .filter(([k,v]) => k !== "licenseHash" && v != null)
    .sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0)
    .map(([key,value]) => escapeJavaProperty(key, true) + "=" +
      escapeJavaProperty(value, false) + "\n").join("");
}
export async function buildReferenceDemoProperties(fields, signBytes) {
  if (typeof signBytes !== "function") throw new Error("Не передана DSA-подпись");
  const {header, data} = propertiesForDemoProduct(fields);
  const hashSource = serializeForLicenseHash(data);
  const hashBytes = await signBytes(new TextEncoder().encode(hashSource));
  let binary = "";
  for (const byte of hashBytes) binary += String.fromCharCode(byte);
  data.set("licenseHash", btoa(binary));
  // Match reference HashMap(32), including invisible null entries and resize.
  return header + "\n" + javaPropertyEntries(data).filter(([,v]) => v != null)
    .map(([key,value]) => key + "=" + value).join("\n");
}

