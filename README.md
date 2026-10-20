# David Secure Web Protection

Extensión antivirus de navegador (Chrome, Edge, Brave, Opera y Firefox) que
protege contra webs maliciosas, phishing y conexiones HTTP inseguras.

- **Sin APIs externas** → análisis 100% local y offline (heurísticas).
- **Sin icono personalizado** (usa el por defecto del navegador).
- **i18n**: Español, English, Português (auto según idioma del navegador).

## Probar en Chrome / Edge / Brave / Opera
1. Abre `chrome://extensions` (o `edge://extensions`).
2. Activa "Modo desarrollador".
3. "Cargar descomprimida" → selecciona esta carpeta.

## Probar en Firefox
1. Abre `about:debugging#/runtime/this-firefox`.
2. "Cargar complemento temporal" → selecciona `manifest.json`.

> Firefox 128+ recomendado para soporte completo de Manifest V3.

## Qué detecta
- HTTP sin cifrado
- IPs directas y puertos inusuales
- `@` en la URL, punycode, homógrafos
- TLDs sospechosos (.tk, .xyz, .zip…)
- Palabras clave de phishing
- Suplantación de marcas (paypal, apple, etc.)
- Acortadores, URLs muy largas, codificadas…


