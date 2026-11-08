# Guía Técnica de Estudio — Config & URL Security Inspector

Documento de repaso rápido para defensa técnica en entrevistas. Todo el contenido referencia la implementación real del repositorio.

---

## 1. Arquitectura General

1. **Captura en el DOM (`src/ui/*`):** Los controladores (`envPanelController.js`, `urlPanelController.js`) escuchan eventos del usuario (`input`, `drop`, `submit`) sin contener lógica de negocio.
2. **Análisis Puro (`src/security/*`):** Los controladores invocan funciones puras sin acceso al DOM (`auditEnvContent`, `inspectEndpointUrl`, `computeSha256Hex`) que devuelven objetos de diagnóstico deterministas y testeables en Node (`node --test`).
3. **Estado Inmutable → Render (`src/state/inspectorStore.js`):** El resultado actualiza `createInspectorStore()` mediante snapshots congelados (`Object.freeze`) en RAM volátil, notificando a los suscriptores para re-renderizar solo la vista afectada.

```text
[Evento DOM] ──► [Motor Puro (envAuditor / urlInspector)] ──► [Store Inmutable] ──► [Render UI]
```

---

## 2. Desglose Módulo por Módulo

### A. Módulo `.env` (`src/security/envAuditor.js`)

**Funciones principales:**
- `parseEnvLine(rawLine, lineNumber)`: Clasifica líneas en `blank`, `comment`, `malformed` o `assignment` (soporta prefijo `export`, comillas y comentarios inline).
- `auditEnvContent(rawContent)`: Evalúa reglas de riesgo línea por línea y genera en el mismo pase `sanitizedExample` + mapa de severidades para el editor.
- `calculateShannonEntropy(value)`: Mide aleatoriedad en bits/carácter para detectar secretos débiles (`< 3.2` bits o longitud `< 16`).
- `isLikelyPlaceholder(cleanValue)` y `maskSensitiveValue(rawValue)`: Filtran plantillas inocuas y ofuscan valores sensibles en la UI (`sk_liv••••456`).

**Expresiones Regulares clave y qué buscan:**
- **Parseo `KEY=VALUE`:**
  ```js
  /^\s*(export\s+)?([A-Za-z_][A-Za-z0-9_.-]*)\s*=\s*(.*)$/
  ```
  Extrae clave y valor respetando `export ` opcional.
- **Comentario inline seguro:**
  ```js
  /\s+#/
  ```
  Exige espacio antes de `#` en valores sin comillas para **no truncar** contraseñas reales que incluyan `#` (ej. `clave#2026`).
- **Cadenas de conexión críticas (DSN):**
  ```js
  /^(mongodb(?:\+srv)?|postgres(?:ql)?|mysql|mariadb|redis(?:s)?|amqp(?:s)?|mssql|sqlserver):\/\/(.+)$/i
  ```
  Detecta URIs de bases de datos/brokers; eleva severidad a `ALTA` si halla credenciales incrustadas (`/:\/\/[^:/?#]+:[^@]+@/`) o hosts remotos.
- **Firmas de API Keys y Tokens (`TOKEN_SIGNATURES`):**
  - **JWT:** `/^eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}$/` (3 segmentos Base64URL).
  - **Stripe:** `/^(?:sk|rk)_live_[0-9A-Za-z]{16,}$/` (`ALTA`) y `sk_test_` (`MEDIA`).
  - **Google Cloud / Firebase:** `/^AIza[0-9A-Za-z_-]{33,37}$/`.
  - **AWS IAM:** `/^(?:AKIA|ASIA)[0-9A-Z]{16}$/`.
  - **GitHub PAT:** `/^(?:gh[pousr]_[A-Za-z0-9]{24,}|github_pat_[A-Za-z0-9_]{24,})$/`.
  - **Proveedores IA (OpenAI/Anthropic):** `/^sk-(?:proj-|ant-)?[A-Za-z0-9_-]{20,}$/`.
  - **Llaves privadas PEM:** `/-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/`.
- **Contraseñas y secretos por nombre de variable (sin falsos positivos):**
  ```js
  /(?:^|_)(PASSWORD|PASSWD|PWD|PASS|PASSPHRASE)(?:$|_)/i
  /(?:^|_)(SECRET|PRIVATE_KEY|API_KEY|ACCESS_KEY|AUTH_TOKEN|CLIENT_SECRET|...)(?:$|_)/i
  ```
  Los delimitadores `(?:^|_)` y `(?:$|_)` evitan marcar por error variables inocuas como `BYPASS_CACHE=false` o `COMPASS_HOST`.
- **Fuga en bundle cliente:** `/^(VITE_|NEXT_PUBLIC_|REACT_APP_|PUBLIC_)/i` (alerta adicional si una variable sensible se inyectará en el JS público).

**Cómo opera la sanitización a `.env.example`:**
- Recorre el archivo en un único pase `O(n)`.
- Conserva intactos comentarios `#`, saltos de línea y variables no sensibles (`PORT=4000`, `LOG_LEVEL=info`).
- Si la línea dispara una regla, conserva la clave e inyecta un placeholder contextual (`postgres://<db_user>:<db_password>@localhost:5432/<db_name>`, `change_me_locally`).
- **Idempotencia garantizada:** `isLikelyPlaceholder()` reconoce `<...>`, `replace_with_*` y `change_me*`; re-auditar el `.env.example` generado produce `0` alertas.

---

### B. Módulo URL (`src/security/urlInspector.js`)

**Uso de la API nativa `new URL()`:**
```js
let parsedUrl;
try {
  parsedUrl = new URL(trimmedInput);
} catch (urlParseError) {
  // Detecta si falta esquema (ej. "api.dominio.com/v1") y ofrece autocompletar https://
}
```
Descompone sin regex frágiles: `protocol`, `username`, `password`, `hostname`, `port`, `pathname`, `searchParams` y `hash`.

**Riesgo real que mitiga cada regla:**
- **Protocolo (`inspectProtocol`):**
  - `http:` / `ws:`: Tráfico en claro expuesto a *Man-in-the-Middle* (MITM), robo de sesiones e imposibilidad de usar cookies `Secure` / `HSTS` (`MEDIA` en loopback `localhost`, `ALTA` en red).
  - `javascript:` / `data:`: Vectores directos de **DOM XSS** si la URL se inserta en `href` o redirecciones dinámicas.
- **Query String y Fragmento (`inspectQueryAndFragmentSecrets`):**
  - Evalúa claves (`?token=`, `?key=`, `?auth=`, `?secret=`, `?password=`) y también valores con firma de token (`VALUE_LOOKS_LIKE_TOKEN`, cazando incluso parámetros camuflados como `?t=eyJ...`).
  - **Riesgo mitigado:** Las URLs completas quedan grabadas sin cifrar en *access logs* de proxies/CDNs (Nginx, CloudFront), historial local y se filtran a terceros en la cabecera HTTP `Referer`. También detecta `#access_token=` en `hash` (flujo OAuth Implicit deprecado, expuesto a lectura por XSS).
- **Credenciales en URI (`inspectEmbeddedCredentials`):**
  - Detecta `parsedUrl.username` o `parsedUrl.password` (`user:password@host`, deprecado por RFC 3986 §3.2.1).
  - **Riesgo mitigado:** Exposición en claro en logs de red/procesos, ataques de phishing por confusión de host y fallos en cliente (`fetch()` bloquea URLs con credenciales embebidas).
- **Puertos Expuestos (`inspectPortExposure`):**
  - **Bases de datos/infra (`27017` Mongo, `5432` Postgres, `3306` MySQL, `6379` Redis, `9200` Elastic → `ALTA`):** Exposición directa de motores de datos fuera de una VPC privada a fuerza bruta, CVEs de protocolo y SSRF.
  - **Desarrollo/App (`3000`, `5000`, `8080`, `5173` → `MEDIA`):** Acceso directo al proceso de aplicación saltando el *Reverse Proxy* endurecido (sin WAF, *rate-limiting* ni terminación TLS centralizada en `:443`).

---

### C. Manejo de Errores y Seguridad del Navegador

- **Por qué corre 100% en el cliente:** Enviar un `.env` con claves `sk_live_` o DSNs de producción a un backend externo rompería el principio de confidencialidad y convertiría al servidor en objetivo crítico. Aquí nada sale de la memoria RAM de la pestaña, bloqueado a nivel navegador mediante `Content-Security-Policy: ... connect-src 'none'` en `index.html`.
- **Qué problema de CORS evita:** Un analizador en navegador que intente ejecutar `fetch(urlDestino)` contra APIs de terceros fallará sistemáticamente por la política **Same-Origin / CORS** (falta de cabecera `Access-Control-Allow-Origin` en el destino) y además filtraría los secretos de la URL en logs DNS y del servidor remoto. La inspección estática con `new URL()` evita por completo el *preflight* y el bloqueo CORS.
- **Controles defensivos implementados:**
  - `FileReader` acotado a `512 KB` y rechazo de archivos binarios buscando bytes nulos (`content.includes('\u0000')`).
  - Degradación limpia con `try/catch` en `crypto.subtle` y `navigator.clipboard` cuando se prueba por IP local sin HTTPS (*non-secure context*).
  - Sanitización obligatoria con `escapeHtml()` antes de cualquier `innerHTML` para neutralizar **auto-XSS**.

---

## 3. "Cheat Sheet" para Entrevistas

### Pregunta 1: *"¿Por qué no guardaste el historial en `localStorage` para mejorar la UX ni verificaste si el endpoint responde con `fetch()`?"*
> **Respuesta:** "Por modelo de amenazas. Guardar variables `.env` o URLs con tokens en `localStorage` escribe secretos en texto plano en el disco del navegador, dejándolos expuestos a cualquier extensión o vulnerabilidad XSS futura; por eso el store vive solo en memoria volátil congelada (`Object.freeze`). Y respecto a `fetch()`, disparar peticiones desde el navegador chocaría contra bloqueos CORS en casi cualquier API privada y filtraría los query tokens reales en logs externos. Reforcé esa garantía con `CSP connect-src 'none'`."

### Pregunta 2: *"¿Cómo implementaste el resaltado sintáctico del editor `.env` sin librerías externas y sin desfasar el cursor?"*
> **Respuesta:** "Superpuse un `<textarea>` transparente (`caret-color` cyan) sobre un `<pre><code>` sincronizado en `scrollTop` y `scrollLeft`. Para evitar el desfase clásico de subpíxel entre el texto y el cursor, ambos comparten la clase `.env-editor-metrics` (`white-space: pre`, mismo `font-size` de `16px` en móvil para evitar auto-zoom en iOS) y `envHighlighter.js` solo inyecta clases de `color` y `background-color` en los `<span>`, nunca `padding`, `border` ni `font-weight`. Además, todo texto pasa por `escapeHtml()` para impedir DOM XSS al pegar payloads maliciosos."

### Pregunta 3: *"Las Regex para detectar secretos suelen dar muchos falsos positivos. ¿Cómo lo mitigaste en tu motor?"*
> **Respuesta:** "Con tres capas en `envAuditor.js`: primero, límites de segmento `(?:^|_)(PASSWORD|PASS)(?:$|_)` para que claves legítimas como `BYPASS_CACHE` no disparen alertas; segundo, separar comentarios inline solo ante espacio más almohadilla (`/\s+#/`) para no partir contraseñas con `#`; y tercero, un detector de placeholders (`isLikelyPlaceholder`) validado con tests unitarios en `node:test` que garantiza idempotencia: si vuelves a auditar el `.env.example` recién generado, el motor reporta exactamente cero hallazgos."
