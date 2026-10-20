const params = new URLSearchParams(location.search);
const targetUrl = params.get("url") || "";
const tabId = parseInt(params.get("tabId"), 10);
const score = params.get("score") || "0";

// i18n
document.querySelectorAll("[data-i18n]").forEach(el => {
  const msg = chrome.i18n.getMessage(el.dataset.i18n);
  if (msg) el.textContent = msg;
});

document.getElementById("targetUrl").textContent = targetUrl;
document.getElementById("score").textContent = score + "/100";

// Mostrar motivos (analiza de nuevo para obtenerlos)
try {
  const analysis = analyzeURL(targetUrl);
  const ul = document.getElementById("reasons");
  ul.innerHTML = analysis.reasons
    .map(r => `<li>${reasonText(r.code, r.detail)}</li>`)
    .join("");
} catch (e) {}

document.getElementById("continueBtn").addEventListener("click", () => {
  chrome.runtime.sendMessage({ type: "continue", tabId, url: targetUrl });
});

document.getElementById("backBtn").addEventListener("click", () => {
  if (history.length > 1) history.back();
  else chrome.tabs.update(tabId, { url: "about:newtab" });
});