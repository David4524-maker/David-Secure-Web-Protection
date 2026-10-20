const SETTINGS_KEY = "dswp_settings";

function applyI18n() {
  document.querySelectorAll("[data-i18n]").forEach(el => {
    const msg = chrome.i18n.getMessage(el.dataset.i18n);
    if (msg) el.textContent = msg;
  });
  document.querySelectorAll("[data-i18n-placeholder]").forEach(el => {
    const msg = chrome.i18n.getMessage(el.dataset.i18nPlaceholder);
    if (msg) el.placeholder = msg;
  });
}

function levelLabel(level) {
  return chrome.i18n.getMessage(level) || level;
}

function renderResult(container, analysis) {
  container.classList.remove("hidden", "safe", "warning", "danger");
  container.classList.add(analysis.level);
  let reasonsHTML = "";
  if (analysis.reasons.length === 0) {
    reasonsHTML = `<li>${chrome.i18n.getMessage("noIssues") || "Sin incidencias"}</li>`;
  } else {
    reasonsHTML = analysis.reasons
      .map(r => `<li>${reasonText(r.code, r.detail)}</li>`)
      .join("");
  }
  container.innerHTML = `
    <div class="headline">
      <span>${levelLabel(analysis.level)}</span>
      <span class="badge">${chrome.i18n.getMessage("score") || "Riesgo"}: ${analysis.score}/100</span>
    </div>
    <ul class="reasons">${reasonsHTML}</ul>
  `;
}

async function getSettings() {
  const r = await chrome.storage.sync.get(SETTINGS_KEY);
  return Object.assign(
    { enabled: true, blockDangerous: true, warnHTTP: true, warnMalicious: true },
    r[SETTINGS_KEY] || {}
  );
}

async function saveSettings(patch) {
  const cur = await getSettings();
  const next = Object.assign({}, cur, patch);
  await chrome.storage.sync.set({ [SETTINGS_KEY]: next });
}

async function init() {
  applyI18n();
  const settings = await getSettings();
  document.getElementById("enabledToggle").checked = settings.enabled;
  document.getElementById("blockDangerous").checked = settings.blockDangerous;
  document.getElementById("warnHTTP").checked = settings.warnHTTP;
  document.getElementById("warnMalicious").checked = settings.warnMalicious;

  // URL actual
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const currentUrlEl = document.getElementById("currentUrl");
  const currentStatus = document.getElementById("currentStatus");
  if (tab && tab.url && tab.url.startsWith("http")) {
    currentUrlEl.textContent = tab.url;
    const a = analyzeURL(tab.url);
    currentStatus.textContent = levelLabel(a.level);
    currentStatus.className = "status-badge " + a.level;
  } else {
    currentUrlEl.textContent = "—";
  }

  // Analizador
  const urlInput = document.getElementById("urlInput");
  const result = document.getElementById("result");
  const analyzeBtn = document.getElementById("analyzeBtn");

  function runAnalyze() {
    let u = urlInput.value.trim();
    if (!u) return;
    if (!/^[a-z]+:\/\//i.test(u)) u = "http://" + u;
    renderResult(result, analyzeURL(u));
  }
  analyzeBtn.addEventListener("click", runAnalyze);
  urlInput.addEventListener("keydown", e => { if (e.key === "Enter") runAnalyze(); });

  // Toggles
  document.getElementById("enabledToggle").addEventListener("change", e =>
    saveSettings({ enabled: e.target.checked }));
  document.getElementById("blockDangerous").addEventListener("change", e =>
    saveSettings({ blockDangerous: e.target.checked }));
  document.getElementById("warnHTTP").addEventListener("change", e =>
    saveSettings({ warnHTTP: e.target.checked }));
  document.getElementById("warnMalicious").addEventListener("change", e =>
    saveSettings({ warnMalicious: e.target.checked }));
}

document.addEventListener("DOMContentLoaded", init);