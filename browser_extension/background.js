/* Qproxy Browser Filter: network filtering via declarativeNetRequest.
   Works with Firefox MV3 event pages and Chromium MV3 service workers. */
"use strict";

const QPROXY_RULES_URL = "http://127.0.0.1:8900/api/browser-rules";
const RULE_ID_START = 10001;
const RULE_ID_END = 10800;
const DISALLOWED_RESOURCES = new Set(["image", "media", "main_frame"]);
const ALLOWED_TYPES = new Set(["script", "xmlhttprequest", "sub_frame", "ping"]);
const SYNC_ALARM = "qproxy-rule-refresh";

function validQproxyRule(rule) {
  if (!rule || !Number.isInteger(rule.id)) return false;
  if (rule.id < RULE_ID_START || rule.id > RULE_ID_END) return false;
  if (!["block", "allow"].includes(rule.action?.type)) return false;
  const condition = rule.condition;
  if (!condition || !Array.isArray(condition.initiatorDomains)) return false;
  if (condition.initiatorDomains.length !== 1 ||
      condition.initiatorDomains[0] !== "youtube.com") return false;
  if (!Array.isArray(condition.resourceTypes) || !condition.resourceTypes.length ||
      condition.resourceTypes.some(type => DISALLOWED_RESOURCES.has(type) || !ALLOWED_TYPES.has(type))) return false;
  if (condition.requestDomains?.some(host =>
      ["youtube.com", "googlevideo.com", "ytimg.com"].some(
        protectedHost => host === protectedHost || host.endsWith("." + protectedHost)
      ))) return false;
  return true;
}

async function syncQproxyRules() {
  try {
    const response = await fetch(QPROXY_RULES_URL, {cache: "no-store", signal: AbortSignal.timeout(6000)});
    if (!response.ok) throw new Error("Qproxy indisponível (" + response.status + ")");
    const payload = await response.json();
    if (payload.version !== 1 || !Array.isArray(payload.rules) || payload.rules.length > 800) {
      throw new Error("Conjunto de regras inválido");
    }
    // A sincronização é estritamente atômica. Se o Qproxy ainda não
    // gerou regras, preservar o conjunto anterior até ter dados válidos.
    if (!payload.rules.length) return;
    const ids = new Set();
    for (const rule of payload.rules) {
      if (!validQproxyRule(rule) || ids.has(rule.id)) throw new Error("Regra insegura ou duplicada");
      ids.add(rule.id);
    }

    const previous = await chrome.declarativeNetRequest.getDynamicRules();
    const owned = previous.filter(r => r.id >= RULE_ID_START && r.id <= RULE_ID_END);
    if (JSON.stringify(owned) === JSON.stringify(payload.rules)) return;

    await chrome.declarativeNetRequest.updateDynamicRules({
      removeRuleIds: owned.map(rule => rule.id),
      addRules: payload.rules
    });
    console.info("[Qproxy] Filtros do navegador sincronizados:", payload.rules.length);
  } catch (error) {
    // Falhas de rede e downloads não removem filtros já existentes.
    console.warn("[Qproxy] Filtros anteriores preservados:", error?.message || String(error));
  }
}

chrome.runtime.onInstalled.addListener(() => { void syncQproxyRules(); });
chrome.runtime.onStartup.addListener(() => { void syncQproxyRules(); });
chrome.alarms.onAlarm.addListener(alarm => {
  if (alarm.name === SYNC_ALARM) void syncQproxyRules();
});
chrome.alarms.create(SYNC_ALARM, {periodInMinutes: 15});
void syncQproxyRules();
