/* David Secure Web Protection — Motor de análisis local (offline, sin APIs) */

function analyzeURL(urlString) {
  const result = {
    url: urlString,
    score: 0,
    level: "safe",
    reasons: [],
    isHttps: false,
    hostname: "",
    protocol: ""
  };

  let url;
  try {
    url = new URL(urlString);
  } catch (e) {
    result.reasons.push({ code: "invalid_url", weight: 100 });
    result.score = 100;
    result.level = "danger";
    return result;
  }

  result.hostname = url.hostname.toLowerCase();
  result.protocol = url.protocol;
  const host = result.hostname;
  const fullUrl = urlString.toLowerCase();
  const pathLower = url.pathname.toLowerCase();

  // Protocolo
  if (url.protocol === "https:") {
    result.isHttps = true;
  } else if (url.protocol === "http:") {
    result.reasons.push({ code: "http", weight: 25 });
  } else if (["data:", "javascript:", "vbscript:", "file:"].includes(url.protocol)) {
    result.reasons.push({ code: "dangerous_protocol", weight: 100 });
    result.score = 100;
    result.level = "danger";
    return result;
  }

  // IP directa
  const isIPv4 = /^\d{1,3}(\.\d{1,3}){3}$/.test(host);
  const isIPv6 = host.startsWith("[") || (/^[0-9a-f:]+$/i.test(host) && host.includes(":"));
  if (isIPv4 || isIPv6) result.reasons.push({ code: "ip_address", weight: 40 });

  // Símbolo @ en la parte previa al query
  if (urlString.split("?")[0].includes("@")) {
    result.reasons.push({ code: "at_symbol", weight: 50 });
  }

  // Punycode
  if (host.includes("xn--")) result.reasons.push({ code: "punycode", weight: 45 });

  // TLD sospechoso
  const suspiciousTLDs = [
    ".zip", ".mov", ".top", ".xyz", ".tk", ".ml", ".ga", ".cf", ".gq",
    ".work", ".click", ".country", ".kim", ".science", ".party", ".review",
    ".loan", ".download", ".stream", ".racing", ".win", ".bid", ".vip",
    ".cam", ".sbs", ".rest", ".monster", ".quest"
  ];
  for (const tld of suspiciousTLDs) {
    if (host.endsWith(tld)) {
      result.reasons.push({ code: "suspicious_tld", weight: 25, detail: tld });
      break;
    }
  }

  // Subdominios excesivos
  const parts = host.split(".").filter(Boolean);
  if (parts.length > 4) result.reasons.push({ code: "many_subdomains", weight: 20 });

  // Longitud de URL
  if (urlString.length > 200) result.reasons.push({ code: "long_url", weight: 20 });
  if (urlString.length > 500) result.reasons.push({ code: "very_long_url", weight: 30 });

  // Puerto inusual
  if (url.port && !["80", "443", "8080", "8443"].includes(url.port)) {
    result.reasons.push({ code: "unusual_port", weight: 15, detail: url.port });
  }

  // Palabras clave de phishing
  const phishKeywords = [
    "login-verify", "verify-account", "secure-login", "account-update",
    "confirm-identity", "signin", "paypal", "netflix", "bank", "wallet",
    "password", "update-info", "unlock", "recovery", "suspend", "urgent",
    "alert", "limited-time", "click-here", "free-gift", "prize", "winner",
    "you-won", "bitcoin", "crypto-giveaway", "refund", "tax-refund",
    "verify", "verification", "billing", "invoice", "package", "delivery"
  ];
  let kwHits = 0;
  for (const kw of phishKeywords) {
    if (host.includes(kw) || pathLower.includes(kw)) kwHits++;
  }
  if (kwHits > 0) {
    result.reasons.push({ code: "phishing_keywords", weight: Math.min(60, 15 * kwHits) });
  }

  // Suplantación de marcas
  const brands = [
    "paypal", "apple", "google", "microsoft", "amazon", "facebook",
    "netflix", "bankofamerica", "wellsfargo", "chase", "instagram",
    "whatsapp", "linkedin", "outlook", "gmail", "yahoo", "dropbox",
    "coinbase", "binance", "steam", "twitter", "tiktok", "spotify"
  ];
  for (const brand of brands) {
    if (host.includes(brand)) {
      const legit = [`${brand}.com`, `${brand}.net`, `${brand}.org`, `${brand}.co`, `${brand}.io`, `${brand}.es`, `${brand}.pt`];
      if (!legit.some(d => host === d || host.endsWith("." + d))) {
        result.reasons.push({ code: "brand_impersonation", weight: 40, detail: brand });
        break;
      }
    }
  }

  // Muchos guiones en dominio principal
  const mainDomain = parts.length >= 2 ? parts[parts.length - 2] : host;
  if ((mainDomain.match(/-/g) || []).length >= 2) {
    result.reasons.push({ code: "many_hyphens", weight: 20 });
  }

  // Acortadores
  const shorteners = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "adf.ly", "bit.do", "cutt.ly", "rb.gy", "shorturl.at"
  ];
  if (shorteners.includes(host)) {
    result.reasons.push({ code: "url_shortener", weight: 20 });
  }

  // Codificación excesiva
  const encoded = fullUrl.match(/%[0-9a-f]{2}/gi);
  if (encoded && encoded.length > 8) result.reasons.push({ code: "encoded_url", weight: 20 });

  // Demasiados puntos
  if ((host.match(/\./g) || []).length >= 4) {
    result.reasons.push({ code: "many_dots", weight: 20 });
  }

  // Doble slash en path
  if (url.pathname.includes("//")) {
    result.reasons.push({ code: "double_slash", weight: 15 });
  }

  // Score final
  result.score = Math.min(100, result.reasons.reduce((s, r) => s + r.weight, 0));
  if (result.score >= 60) result.level = "danger";
  else if (result.score >= 25) result.level = "warning";
  else result.level = "safe";

  return result;
}

function reasonText(code, detail) {
  const map = {
    invalid_url: "reasonInvalidUrl",
    http: "reasonHttp",
    dangerous_protocol: "reasonDangerousProtocol",
    ip_address: "reasonIpAddress",
    at_symbol: "reasonAtSymbol",
    punycode: "reasonPunycode",
    suspicious_tld: "reasonSuspiciousTld",
    many_subdomains: "reasonManySubdomains",
    long_url: "reasonLongUrl",
    very_long_url: "reasonVeryLongUrl",
    unusual_port: "reasonUnusualPort",
    phishing_keywords: "reasonPhishingKeywords",
    brand_impersonation: "reasonBrandImpersonation",
    many_hyphens: "reasonManyHyphens",
    url_shortener: "reasonUrlShortener",
    encoded_url: "reasonEncodedUrl",
    many_dots: "reasonManyDots",
    double_slash: "reasonDoubleSlash"
  };
  const key = map[code] || "reasonUnknown";
  let txt = (typeof chrome !== "undefined" && chrome.i18n)
    ? (chrome.i18n.getMessage(key) || key)
    : key;
  if (detail) txt += ` (${detail})`;
  return txt;
}