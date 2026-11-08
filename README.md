# Config & URL Security Inspector

SPA **100% Client-Side** construida con HTML5 semántico, Tailwind CSS (estética Argon Dashboard Dark) y Vanilla JavaScript modular para auditar archivos `.env` y analizar estáticamente la seguridad de URLs/endpoints sin tráfico de red externo (`CSP connect-src 'none'`).

## Arquitectura Modular

- `src/state/inspectorStore.js` — Estado reactivo e inmutable exclusivamente en memoria volátil (nunca persiste secretos en `localStorage`).
- `src/security/envAuditor.js` — Motor puro de auditoría `.env` línea por línea y generador idempotente de `.env.example`.
- `src/security/urlInspector.js` — Analizador estático puro basado en `new URL()` (protocolo TLS, credenciales `user:pass@host`, fugas en Query String/Referer y puertos críticos).
- `src/security/cryptoDigest.js` — Huella de integridad local `SHA-256` y generador de secretos CSPRNG de 256 bits vía Web Crypto API.
- `src/ui/*` — Controladores de eventos, resaltador sintáctico sincronizado con `<textarea>` y notificaciones accesibles (`aria-live="polite"`).

## Ejecución Local

No requiere instalar dependencias para ejecutarse:

```bash
npm run dev
# Abre http://localhost:5173 en tu navegador
```

Ejecutar la suite de pruebas unitarias del motor de seguridad (Node.js >= 20):

```bash
npm test
```
# Config-And-URL-Security-Inspector
# Config-And-URL-Security-Inspector
