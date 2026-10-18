"use strict";
const el = id => document.getElementById(id);
const dnr = chrome.declarativeNetRequest;

function displayDate(iso) {
  if (!iso) return "Nunca";
  const date = new Date(iso);
  return Number.isNaN(date.getTime()) ? "Data inválida" : date.toLocaleString("pt-BR");
}

async function refresh() {
  const stored = await chrome.storage.local.get("qproxyStatus");
  const status = stored.qproxyStatus || {};
  el("connection").textContent = status.connected ? "Conectado" : "Desconectado";
  el("connection").className = "value " + (status.connected ? "good" : "bad");
  el("updated").textContent = displayDate(status.updatedAt);
  el("error").textContent = status.error || "";

  try {
    const [dynamic, enabled] = await Promise.all([
      dnr.getDynamicRules(), dnr.getEnabledRulesets()
    ]);
    const number = dynamic.filter(rule => rule.id >= 10001 && rule.id <= 10800).length;
    el("dynamic").textContent = String(number);
    el("dynamic").className = "value " + (number ? "good" : "bad");
    const active = enabled.includes("youtube_network_ads");
    el("static").textContent = active ? "Sim" : "Não";
    el("static").className = "value " + (active ? "good" : "bad");
  } catch (error) {
    el("error").textContent = "Erro ao consultar regras: " + (error?.message || String(error));
  }

  if (typeof dnr.testMatchOutcome === "function") {
    try {
      const result = await dnr.testMatchOutcome({
        url: "https://googleads.g.doubleclick.net/test.js",
        initiator: "https://www.youtube.com",
        type: "script"
      });
      const matched = (result.matchedRules || []).length > 0;
      el("test").textContent = matched ? "Regra detectada" : "Nenhuma regra";
      el("test").className = "value " + (matched ? "good" : "bad");
    } catch {
      el("test").textContent = "Não disponível";
    }
  } else {
    el("test").textContent = "Não disponível";
  }
}

el("sync").addEventListener("click", async () => {
  const button = el("sync");
  button.disabled = true;
  try {
    const result = await chrome.runtime.sendMessage({type: "QPROXY_SYNC_NOW"});
    if (!result?.ok) el("error").textContent = result?.error || "Falha ao sincronizar";
  } catch (error) {
    el("error").textContent = error?.message || String(error);
  } finally {
    await refresh();
    button.disabled = false;
  }
});
el("refresh").addEventListener("click", refresh);
void refresh();