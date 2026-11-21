/* Qproxy browser filter + observable synchronization state.
   Supports YouTube-scoped rules (10001..10800) and safe third-party web rules
   (20001..22000). Does not touch YouTube video playback or collect visited URLs. */
"use strict";

const RULES_URL = "http://127.0.0.1:8900/api/browser-rules";
const RULE_FIRST = 10001;
const RULE_LAST = 10800;
const WEB_RULE_FIRST = 20001;
const WEB_RULE_LAST = 22000;
const TYPES = new Set(["script", "xmlhttprequest", "sub_frame", "ping"]);
const PROTECTED = ["youtube.com", "googlevideo.com", "ytimg.com", "youtubei.googleapis.com"];
const ALARM = "qproxy-rule-refresh";
let syncInProgress = null;

function protectedHost(host) {
  return PROTECTED.some(domain => host === domain || host.endsWith("." + domain));
}

function validQproxyRule(rule) {
  if (!rule || !Number.isInteger(rule.id) || rule.id < RULE_FIRST || rule.id > RULE_LAST ||
      !["block", "allow"].includes(rule.action?.type)) return false;
  const c = rule.condition;
  if (!c || !Array.isArray(c.initiatorDomains) ||
      c.initiatorDomains.length !== 1 || c.initiatorDomains[0] !== "youtube.com") return false;
  if (!Array.isArray(c.resourceTypes) || c.resourceTypes.length === 0 ||
      c.resourceTypes.some(type => !TYPES.has(type))) return false;
  if (c.requestDomains?.some(protectedHost)) return false;
  if (c.urlFilter && (
    typeof c.urlFilter !== "string" ||
    c.urlFilter.length > 512 ||
    !c.urlFilter.startsWith("||")
  )) return false;
  if (c.urlFilter && PROTECTED.some(host => {
    const start = "||" + host + "/";
    return c.urlFilter.startsWith(start) &&
      !c.urlFilter.startsWith(start + "pagead/") &&
      !c.urlFilter.startsWith(start + "api/stats/ads");
  })) return false;
  return Boolean(c.requestDomains?.length || c.urlFilter);
}

function validWebRule(rule) {
  if (!rule || !Number.isInteger(rule.id) || rule.id < WEB_RULE_FIRST || rule.id > WEB_RULE_LAST ||
      rule.action?.type !== "block") return false;
  const c = rule.condition;
  if (!c || c.domainType !== "thirdParty") return false;
  if (!Array.isArray(c.resourceTypes) || c.resourceTypes.length === 0 ||
      c.resourceTypes.some(type => !TYPES.has(type))) return false;
  if (!Array.isArray(c.requestDomains) || c.requestDomains.length !== 1) return false;
  if (c.requestDomains.some(protectedHost)) return false;
  return true;
}

function isOwnedRuleId(id) {
  return (id >= RULE_FIRST && id <= RULE_LAST) || (id >= WEB_RULE_FIRST && id <= WEB_RULE_LAST);
}

function fingerprint(text) {
  let h = 2166136261;
  for (let i = 0; i < text.length; i++) {
    h ^= text.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return (h >>> 0).toString(16);
}

async function saveStatus(delta) {
  try {
    const previous = (await chrome.storage.local.get("qproxyStatus")).qproxyStatus || {};
    await chrome.storage.local.set({qproxyStatus: {...previous, ...delta}});
  } catch (error) {
    console.warn("[Qproxy] Não foi possível salvar diagnóstico:", String(error));
  }
}

async function performSync() {
  const attemptedAt = new Date().toISOString();
  await saveStatus({attemptedAt});
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 6000);
    let response;
    try {
      response = await fetch(RULES_URL, {
        cache: "no-store", signal: controller.signal
      });
    } finally {
      clearTimeout(timeout);
    }
    if (!response.ok) throw Error("Painel Qproxy retornou HTTP " + response.status);
    const payload = await response.json();
    if (payload.version !== 1 || !Array.isArray(payload.rules) ||
        payload.rules.length > 800) throw Error("Lista de regras inválida");
    if (!payload.rules.length) {
      throw Error("Nenhuma regra de navegador gerada. Atualize as listas no painel.");
    }

    const webRules = Array.isArray(payload.web_rules) ? payload.web_rules.slice(0, 2000) : [];
    const ids = new Set();
    const combined = [];

    for (const rule of payload.rules) {
      if (!validQproxyRule(rule) || ids.has(rule.id)) throw Error("Lista contém regra duplicada ou insegura");
      ids.add(rule.id);
      combined.push(rule);
    }
    for (const rule of webRules) {
      if (!validWebRule(rule) || ids.has(rule.id)) continue;
      ids.add(rule.id);
      combined.push(rule);
    }

    const signature = fingerprint(JSON.stringify(combined));
    const loaded = await chrome.declarativeNetRequest.getDynamicRules();
    const owned = loaded.filter(rule => isOwnedRuleId(rule.id));
    const previous = (await chrome.storage.local.get("qproxyStatus")).qproxyStatus || {};
    if (previous.signature !== signature || owned.length !== combined.length) {
      await chrome.declarativeNetRequest.updateDynamicRules({
        removeRuleIds: owned.map(rule => rule.id),
        addRules: combined
      });
    }
    // Confirm what the browser actually accepted, not just downloaded.
    const verified = await chrome.declarativeNetRequest.getDynamicRules();
    const count = verified.filter(rule => isOwnedRuleId(rule.id)).length;
    if (count !== combined.length) {
      throw Error("Navegador aceitou apenas " + count + " de " + combined.length + " regras");
    }
    await saveStatus({
      connected: true,
      updatedAt: new Date().toISOString(),
      signature,
      dynamicRules: count,
      error: null
    });
    console.info("[Qproxy] Regras ativas no navegador:", count);
    return {ok: true, count};
  } catch (error) {
    const message = error?.message || String(error);
    await saveStatus({connected: false, error: message});
    console.warn("[Qproxy] Sincronização falhou:", message);
    return {ok: false, error: message};
  }
}

function syncQproxyRules() {
  if (!syncInProgress) {
    syncInProgress = performSync().finally(() => {
      syncInProgress = null;
    });
  }
  return syncInProgress;
}

chrome.runtime.onInstalled.addListener(() => { void syncQproxyRules(); });
chrome.runtime.onStartup.addListener(() => { void syncQproxyRules(); });
chrome.alarms.onAlarm.addListener(alarm => {
  if (alarm.name === ALARM) void syncQproxyRules();
});
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message?.type !== "QPROXY_SYNC_NOW" || sender.id !== chrome.runtime.id) return;
  void syncQproxyRules().then(sendResponse);
  return true;
});
// Tentar novamente quando o Qproxy termina o primeiro download após iniciar.
chrome.alarms.create(ALARM, {periodInMinutes: 2});
void syncQproxyRules();
