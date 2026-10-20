/* Service worker: intercepta navegación y bloquea/adverttice */
importScripts("analyzer.js");

const SETTINGS_KEY = "dswp_settings";
const DEFAULT_SETTINGS = {
  enabled: true,
  blockDangerous: true,
  warnHTTP: true,
  warnMalicious: true
};

async function getSettings() {
  const r = await chrome.storage.sync.get(SETTINGS_KEY);
  return Object.assign({}, DEFAULT_SETTINGS, r[SETTINGS_KEY] || {});
}

const allowedTabs = new Set();

async function checkNavigation(details) {
  if (details.frameId !== 0) return;
  if (!details.url || !details.url.startsWith("http")) return;
  if (details.url.startsWith(chrome.runtime.getURL(""))) return;

  const settings = await getSettings();
  if (!settings.enabled) return;

  const tabId = details.tabId;
  if (allowedTabs.has(tabId)) return;

  const analysis = analyzeURL(details.url);
  if (analysis.level === "safe") return;

  const shouldBlock = analysis.level === "danger" && settings.blockDangerous;
  const shouldWarnHTTP = settings.warnHTTP && analysis.reasons.some(r => r.code === "http");

  if (shouldBlock || shouldWarnHTTP) {
    const warnUrl = chrome.runtime.getURL("warning.html")
      + "?url=" + encodeURIComponent(details.url)
      + "&tabId=" + tabId
      + "&score=" + analysis.score
      + "&level=" + analysis.level;
    try { chrome.tabs.update(tabId, { url: warnUrl }); } catch (e) {}
    return;
  }

  if (analysis.level === "warning" && settings.warnMalicious) {
    try {
      chrome.action.setBadgeText({ text: "!", tabId });
      chrome.action.setBadgeBackgroundColor({ color: "#f0ad4e", tabId });
    } catch (e) {}
  }
}

chrome.webNavigation.onBeforeNavigate.addListener(checkNavigation);

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === "analyze" && msg.url) {
    sendResponse(analyzeURL(msg.url));
    return true;
  }
  if (msg.type === "continue" && msg.tabId != null && msg.url) {
    allowedTabs.add(msg.tabId);
    chrome.tabs.update(msg.tabId, { url: msg.url });
    sendResponse({ ok: true });
    return true;
  }
});

chrome.tabs.onRemoved.addListener((tabId) => allowedTabs.delete(tabId));