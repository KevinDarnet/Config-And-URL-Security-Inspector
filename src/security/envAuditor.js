/**
 * Motor puro de auditoría para archivos .env y generación de .env.example sanitizado.
 * Sin dependencias del DOM para permitir ejecución directa en tests unitarios o CI.
 */

export const SEVERITY = Object.freeze({
  HIGH: 'ALTA',
  MEDIUM: 'MEDIA',
  LOW: 'BAJA'
});

const CONNECTION_URI_PATTERN = /^(mongodb(?:\+srv)?|postgres(?:ql)?|mysql|mariadb|redis(?:s)?|amqp(?:s)?|mssql|sqlserver):\/\/(.+)$/i;

const TOKEN_SIGNATURES = [
  {
    id: 'jwt-token',
    label: 'Token JWT firmado detectado',
    severity: SEVERITY.HIGH,
    pattern: /^eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}$/,
    placeholder: 'replace_with_signed_jwt_or_remove',
    remediation: 'No almacenes tokens de sesión o servicio pre-firmados en .env; emítelos dinámicamente con expiración corta (exp).'
  },
  {
    id: 'stripe-live-key',
    label: 'Clave privada de producción Stripe (sk_live / rk_live)',
    severity: SEVERITY.HIGH,
    pattern: /^(?:sk|rk)_live_[0-9A-Za-z]{16,}$/,
    placeholder: 'sk_test_replace_with_stripe_key',
    remediation: 'Revoca esta clave en el dashboard de Stripe si estuvo en Git e inyéctala desde un gestor de secretos (Vault, Doppler, Secret Manager).'
  },
  {
    id: 'stripe-test-key',
    label: 'Clave de entorno de pruebas Stripe (sk_test / rk_test)',
    severity: SEVERITY.MEDIUM,
    pattern: /^(?:sk|rk)_test_[0-9A-Za-z]{16,}$/,
    placeholder: 'sk_test_replace_with_stripe_key',
    remediation: 'Aunque sea de sandbox, expone datos de pruebas y cuotas de API de tu cuenta Stripe; usa claves individuales por desarrollador.'
  },
  {
    id: 'google-api-key',
    label: 'API Key de Google Cloud / Firebase (AIza)',
    severity: SEVERITY.HIGH,
    pattern: /^AIza[0-9A-Za-z_-]{33,37}$/,
    placeholder: 'your_google_cloud_api_key',
    remediation: 'Restringe la clave por HTTP Referrer o dirección IP en Google Cloud Console y evita subirla sin restricciones de cuota.'
  },
  {
    id: 'github-pat',
    label: 'Personal Access Token de GitHub',
    severity: SEVERITY.HIGH,
    pattern: /^(?:gh[pousr]_[A-Za-z0-9]{24,}|github_pat_[A-Za-z0-9_]{24,})$/,
    placeholder: 'ghp_replace_with_scoped_github_token',
    remediation: 'Sustituye tokens personales de larga duración por GitHub Apps o Fine-Grained PATs con permisos mínimos.'
  },
  {
    id: 'llm-provider-key',
    label: 'API Key de proveedor de IA (OpenAI / Anthropic)',
    severity: SEVERITY.HIGH,
    pattern: /^sk-(?:proj-|ant-)?[A-Za-z0-9_-]{20,}$/,
    placeholder: 'sk-replace_with_provider_api_key',
    remediation: 'Nunca expongas claves de inferencia en el repositorio ni en variables accesibles por el cliente; enrútalas desde backend.'
  },
  {
    id: 'slack-or-sendgrid-token',
    label: 'Token de integración (Slack / SendGrid)',
    severity: SEVERITY.HIGH,
    pattern: /^(?:xox[baprs]-[0-9A-Za-z-]{16,}|SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,})$/,
    placeholder: 'replace_with_integration_token',
    remediation: 'Almacena tokens de mensajería y correo transaccional en el almacén cifrado del proveedor CI/CD.'
  },
  {
    id: 'pem-private-key',
    label: 'Clave privada criptográfica PEM en texto plano',
    severity: SEVERITY.HIGH,
    pattern: /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/,
    placeholder: '"-----BEGIN PRIVATE KEY-----\\n<load_from_secret_volume>\\n-----END PRIVATE KEY-----"',
    remediation: 'Monta certificados y llaves privadas como volúmenes en memoria (tmpfs / Kubernetes Secrets) en vez de incrustarlos en texto.'
  }
];

// Límites por guion bajo evitan falsos positivos en claves como BYPASS_CACHE o COMPASS_HOST.
const PASSWORD_KEY_SEGMENT = /(?:^|_)(PASSWORD|PASSWD|PWD|PASS|PASSPHRASE)(?:$|_)/i;
const SECRET_KEY_SEGMENT = /(?:^|_)(SECRET|PRIVATE_KEY|API_KEY|ACCESS_KEY|AUTH_TOKEN|ACCESS_TOKEN|REFRESH_TOKEN|CLIENT_SECRET|SIGNING_KEY|ENCRYPTION_KEY|MASTER_KEY|WEBHOOK_SECRET)(?:$|_)/i;
const CLIENT_EXPOSED_PREFIX = /^(VITE_|NEXT_PUBLIC_|REACT_APP_|PUBLIC_)/i;

const AWS_ACCESS_KEY_ID_PATTERN = /(AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}/;
const INSECURE_HTTP_URL_PATTERN = /http:\/\/[^\s'"<>]*/gi;
const SAFE_HTTP_LOOPBACK_PATTERN = /^http:\/\/(?:localhost|127\.0\.0\.1|\[::1\])(?::\d+)?(?:[/?#]|$)/i;
const HTTP_HIGH_RISK_KEY_PATTERN = /(?:API|PROD|SERVICE|WEBHOOK|ENDPOINT)/i;
const GLOBAL_BIND_KEY_PATTERN = /^(?:HOST|BIND_ADDRESS|LISTEN_ADDR)$/i;
const REVERSE_PROXY_KEY_PATTERN = /(?:REVERSE_PROXY|PROXY_URL|TRUST_PROXY|NGINX|CADDY|TRAEFIK|CLOUDFLARE_TUNNEL)/i;

const PLACEHOLDER_VALUE_PATTERNS = [
  /^<[^<>]+>$/,
  /^\[[^[\]]+\]$/,
  /^\$\{?[A-Za-z_][A-Za-z0-9_]*\}?$/,
  /^(?:your_|replace_with|change_me|changeme|example|placeholder|todo|dummy|sample|insert_)/i,
  /_(?:here|placeholder|example)$/i,
  /^(?:xxx+|\*\*\*+|---+|\.\.\.+)$/i,
  /^AKIA_REPLACE_WITH_KEY_ID$/,
  /^sk_test_replace_with_stripe_key$/
];

const COMMON_WEAK_PASSWORDS = new Set([
  '123456',
  '12345678',
  'password',
  'admin',
  'admin123',
  'root',
  'postgres',
  'qwerty',
  'secret',
  'letmein',
  'test',
  'default'
]);

export function calculateShannonEntropy(value) {
  if (!value || value.length === 0) {
    return 0;
  }
  const frequencies = new Map();
  for (const char of value) {
    frequencies.set(char, (frequencies.get(char) || 0) + 1);
  }

  let entropy = 0;
  const totalLength = value.length;
  for (const count of frequencies.values()) {
    const probability = count / totalLength;
    entropy -= probability * Math.log2(probability);
  }
  return entropy;
}

export function isLikelyPlaceholder(cleanValue) {
  if (!cleanValue) {
    return true;
  }
  const trimmed = cleanValue.trim();
  if (trimmed.length === 0) {
    return true;
  }

  // URIs sanitizadas tipo postgres://<db_user>:<db_password>@localhost:5432/<db_name>
  if (/<[a-z0-9_-]+>/i.test(trimmed)) {
    return true;
  }

  return PLACEHOLDER_VALUE_PATTERNS.some((pattern) => pattern.test(trimmed));
}

export function maskSensitiveValue(rawValue) {
  const clean = String(rawValue ?? '').trim();
  if (!clean) {
    return '(vacío)';
  }

  // En cadenas de conexión ocultamos la contraseña pero dejamos visible esquema y host para contexto.
  if (CONNECTION_URI_PATTERN.test(clean)) {
    return clean.replace(/:\/\/([^:/?#]+):([^@]+)@/, '://$1:••••••••@');
  }

  if (clean.length <= 8) {
    return `${clean.slice(0, 1)}${'•'.repeat(Math.max(clean.length - 1, 4))}`;
  }

  return `${clean.slice(0, 6)}••••${clean.slice(-3)}`;
}

/**
 * Parsea una línea individual de un archivo .env respetando prefijo `export`,
 * comillas simples/dobles y comentarios inline precedidos por espacio (` #`).
 */
export function parseEnvLine(rawLine, lineNumber) {
  const trimmed = rawLine.trim();

  if (trimmed.length === 0) {
    return { kind: 'blank', lineNumber, rawLine };
  }

  if (trimmed.startsWith('#')) {
    return { kind: 'comment', lineNumber, rawLine };
  }

  const assignmentMatch = rawLine.match(/^\s*(export\s+)?([A-Za-z_][A-Za-z0-9_.-]*)\s*=\s*(.*)$/);
  if (!assignmentMatch) {
    return {
      kind: 'malformed',
      lineNumber,
      rawLine
    };
  }

  const [, exportPrefix = '', key, rawRightHandSide] = assignmentMatch;
  const { cleanValue, inlineComment, quoteChar } = extractValueAndInlineComment(rawRightHandSide);

  return {
    kind: 'assignment',
    lineNumber,
    rawLine,
    exportPrefix,
    key,
    cleanValue,
    inlineComment,
    quoteChar
  };
}

function extractValueAndInlineComment(rawRightHandSide) {
  const trimmedRight = rawRightHandSide.trim();
  if (trimmedRight.length === 0) {
    return { cleanValue: '', inlineComment: '', quoteChar: null };
  }

  const firstChar = trimmedRight[0];
  if (firstChar === '"' || firstChar === "'") {
    let closingIndex = -1;
    for (let idx = 1; idx < trimmedRight.length; idx += 1) {
      if (trimmedRight[idx] === firstChar && trimmedRight[idx - 1] !== '\\') {
        closingIndex = idx;
        break;
      }
    }

    if (closingIndex !== -1) {
      const unquoted = trimmedRight.slice(1, closingIndex);
      const trailing = trimmedRight.slice(closingIndex + 1).trim();
      const inlineComment = trailing.startsWith('#') ? ` ${trailing}` : '';
      return { cleanValue: unquoted, inlineComment, quoteChar: firstChar };
    }
  }

  // Solo tratamos `#` como comentario cuando va precedido de espacio para no truncar contraseñas con `#`.
  const commentBoundaryIndex = trimmedRight.search(/\s+#/);
  if (commentBoundaryIndex !== -1) {
    return {
      cleanValue: trimmedRight.slice(0, commentBoundaryIndex).trim(),
      inlineComment: ` ${trimmedRight.slice(commentBoundaryIndex).trim()}`,
      quoteChar: null
    };
  }

  return { cleanValue: trimmedRight, inlineComment: '', quoteChar: null };
}

function sanitizeConnectionUri(uriValue) {
  const schemeMatch = uriValue.match(/^([a-z0-9+.-]+):\/\//i);
  const scheme = schemeMatch ? schemeMatch[1].toLowerCase() : 'postgres';

  if (scheme.startsWith('mongodb+srv')) {
    return 'mongodb+srv://<db_user>:<db_password>@cluster.example.mongodb.net/<db_name>';
  }
  if (scheme.startsWith('mongodb')) {
    return 'mongodb://<db_user>:<db_password>@localhost:27017/<db_name>';
  }
  if (scheme.startsWith('redis')) {
    return `${scheme}://:<redis_password>@localhost:6379/0`;
  }
  if (scheme.startsWith('mysql') || scheme.startsWith('mariadb')) {
    return `${scheme}://<db_user>:<db_password>@localhost:3306/<db_name>`;
  }
  if (scheme.startsWith('amqp')) {
    return `${scheme}://<mq_user>:<mq_password>@localhost:5672/`;
  }

  return `${scheme}://<db_user>:<db_password>@localhost:5432/<db_name>`;
}

function createEnvFinding({
  id,
  lineNumber,
  key,
  category,
  severity,
  title,
  impact,
  evidenceRedacted,
  mitigation,
  suggestedPlaceholder
}) {
  return {
    id,
    line: lineNumber,
    lineNumber,
    key,
    category,
    severity,
    title,
    impact,
    evidenceRedacted,
    maskedPreview: evidenceRedacted,
    mitigation,
    remediation: mitigation,
    suggestedPlaceholder
  };
}

function redactHttpEvidence(rawValue) {
  return rawValue
    .replace(/http:\/\/([^:/?#]+):([^@]+)@/gi, 'http://$1:••••••••@')
    .replace(/([?&](?:token|key|api_key|apikey|auth|secret|password)=)[^&\s]+/gi, '$1••••••••');
}

function sanitizeInsecureHttpValue(rawValue) {
  return rawValue.replace(INSECURE_HTTP_URL_PATTERN, (matchedUrl) =>
    SAFE_HTTP_LOOPBACK_PATTERN.test(matchedUrl) ? matchedUrl : 'https://api.example.com/...'
  );
}

function buildFileAuditContext(parsedEntries) {
  let isNodeProduction = false;
  let hasExplicitReverseProxy = false;

  for (const entry of parsedEntries) {
    if (entry.kind !== 'assignment') {
      continue;
    }

    const { key, cleanValue } = entry;
    if (/^NODE_ENV$/i.test(key) && /^production$/i.test(cleanValue)) {
      isNodeProduction = true;
    }

    if (REVERSE_PROXY_KEY_PATTERN.test(key) && !/^(?:false|0|no|off|)$/i.test(cleanValue)) {
      hasExplicitReverseProxy = true;
    }
  }

  return { isNodeProduction, hasExplicitReverseProxy };
}

function evaluateAssignmentRisk(parsedEntry, fileContext = {}) {
  const { key, cleanValue, lineNumber } = parsedEntry;

  if (isLikelyPlaceholder(cleanValue)) {
    return null;
  }

  const exposedToClientBundle = CLIENT_EXPOSED_PREFIX.test(key);
  const clientBundleWarning = exposedToClientBundle
    ? ' Además, el prefijo expone esta variable en el bundle público del navegador.'
    : '';

  // 1. Cadenas de conexión a motores de datos o brokers de mensajería.
  const uriMatch = cleanValue.match(CONNECTION_URI_PATTERN);
  if (uriMatch) {
    const scheme = uriMatch[1].toLowerCase();
    const hasEmbeddedCredentials = /:\/\/[^:/?#]+:[^@]+@/.test(cleanValue);
    const pointsToLocalhost = /:\/\/(?:[^@]+@)?(?:localhost|127\.0\.0\.1|0\.0\.0\.0)(?::|\/|$)/i.test(cleanValue);
    const severity = hasEmbeddedCredentials || !pointsToLocalhost ? SEVERITY.HIGH : SEVERITY.MEDIUM;
    const evidenceRedacted = maskSensitiveValue(cleanValue);

    return createEnvFinding({
      id: `line-${lineNumber}-conn`,
      lineNumber,
      key,
      category: 'Cadena de Conexión',
      severity,
      title: hasEmbeddedCredentials
        ? `Credenciales incrustadas en URI ${scheme}://`
        : `Cadena de conexión ${scheme}:// en claro`,
      impact: `Variable "${key}" (línea ${lineNumber}) expone una cadena de conexión ${scheme}:// (${evidenceRedacted}).`,
      evidenceRedacted,
      mitigation: `Sustituye el DSN real por placeholders en .env.example e inyecta la URI mediante secretos del entorno de despliegue.${clientBundleWarning}`,
      suggestedPlaceholder: sanitizeConnectionUri(cleanValue)
    });
  }

  // 2. Identificador de clave de acceso AWS (Access Key ID).
  const awsMatch = cleanValue.match(AWS_ACCESS_KEY_ID_PATTERN) || key.match(AWS_ACCESS_KEY_ID_PATTERN);
  if (awsMatch) {
    const matchedId = awsMatch[0];
    const redactedAwsId = `${matchedId.slice(0, 4)}****${matchedId.slice(-4)}`;

    return createEnvFinding({
      id: `line-${lineNumber}-aws-access-key-id`,
      lineNumber,
      key,
      category: 'Identidad Cloud (AWS)',
      severity: SEVERITY.MEDIUM,
      title: 'Identificador de clave de acceso AWS (Access Key ID)',
      impact: 'Aunque un Access Key ID por sí solo no permite autenticación sin su Secret Access Key asociada, identifica de forma unívoca una cuenta de AWS y superficie de ataque ante ataques dirigidos o filtraciones cruzadas.',
      evidenceRedacted: redactedAwsId,
      mitigation: `No hardcodees identificadores fijos de AWS en repositorios. Utiliza roles IAM (ej. IAM Roles for Service Accounts / EC2 Instance Profiles) o AWS STS para asumir identidades temporales.${clientBundleWarning}`,
      suggestedPlaceholder: 'AKIA_REPLACE_WITH_KEY_ID'
    });
  }

  // 3. Firmas conocidas de API Keys, tokens JWT y llaves privadas PEM.
  for (const signature of TOKEN_SIGNATURES) {
    if (signature.pattern.test(cleanValue)) {
      const evidenceRedacted = maskSensitiveValue(cleanValue);
      return createEnvFinding({
        id: `line-${lineNumber}-${signature.id}`,
        lineNumber,
        key,
        category: 'API Key / Token',
        severity: exposedToClientBundle ? SEVERITY.HIGH : signature.severity,
        title: signature.label,
        impact: `Variable "${key}" (línea ${lineNumber}) contiene un secreto o token activo (${evidenceRedacted}).`,
        evidenceRedacted,
        mitigation: `${signature.remediation}${clientBundleWarning}`,
        suggestedPlaceholder: signature.placeholder
      });
    }
  }

  // 4. Detección de URLs con transporte inseguro (HTTP plano, excluyendo loopback local).
  const httpMatches = cleanValue.match(INSECURE_HTTP_URL_PATTERN) || [];
  const nonLocalHttpMatches = httpMatches.filter((url) => !SAFE_HTTP_LOOPBACK_PATTERN.test(url));
  if (nonLocalHttpMatches.length > 0) {
    const severity = HTTP_HIGH_RISK_KEY_PATTERN.test(key) ? SEVERITY.HIGH : SEVERITY.MEDIUM;
    return createEnvFinding({
      id: `line-${lineNumber}-insecure-http`,
      lineNumber,
      key,
      category: 'Transporte Inseguro',
      severity,
      title: 'Protocolo HTTP no cifrado en variable de entorno',
      impact: 'Las peticiones dirigidas a este servicio viajarán en texto plano a través de la red, quedando expuestas a interceptación o manipulación Man-in-the-Middle (MITM).',
      evidenceRedacted: redactHttpEvidence(cleanValue),
      mitigation: `Actualiza la URI a HTTPS (https://) y asegura que el servidor remoto soporte TLS 1.2+.${clientBundleWarning}`,
      suggestedPlaceholder: sanitizeInsecureHttpValue(cleanValue)
    });
  }

  // 5. Variables de contraseña con valor en texto plano.
  if (PASSWORD_KEY_SEGMENT.test(key)) {
    const isWeak = cleanValue.length < 10 || COMMON_WEAK_PASSWORDS.has(cleanValue.toLowerCase());
    const evidenceRedacted = maskSensitiveValue(cleanValue);
    return createEnvFinding({
      id: `line-${lineNumber}-password`,
      lineNumber,
      key,
      category: 'Contraseña en Texto Plano',
      severity: SEVERITY.HIGH,
      title: isWeak
        ? 'Contraseña en texto plano (además débil o por defecto)'
        : 'Contraseña definida en texto plano',
      impact: `Variable "${key}" (línea ${lineNumber}) define una contraseña en texto plano (${evidenceRedacted}).`,
      evidenceRedacted,
      mitigation: `${
        isWeak
          ? 'El valor utiliza una clave predecible o menor a 10 caracteres. Genera una credencial aleatoria de alta entropía y '
          : ''
      }nunca versiones contraseñas reales; usa un gestor de secretos o variables efímeras.${clientBundleWarning}`,
      suggestedPlaceholder: 'change_me_locally'
    });
  }

  // 6. Variables semánticamente sensibles (SECRET, API_KEY, TOKEN, PRIVATE_KEY) con valor concreto.
  if (SECRET_KEY_SEGMENT.test(key)) {
    const entropy = calculateShannonEntropy(cleanValue);
    const isShortOrPredictable = cleanValue.length < 16 || entropy < 3.2;
    const evidenceRedacted = maskSensitiveValue(cleanValue);

    return createEnvFinding({
      id: `line-${lineNumber}-secret-key`,
      lineNumber,
      key,
      category: 'Secreto / Credencial',
      severity: SEVERITY.HIGH,
      title: isShortOrPredictable
        ? 'Secreto de aplicación en claro con baja entropía'
        : 'Secreto o token de aplicación expuesto en claro',
      impact: `Variable "${key}" (línea ${lineNumber}) expone un secreto de aplicación (${evidenceRedacted}).`,
      evidenceRedacted,
      mitigation: `${
        isShortOrPredictable
          ? 'Este secreto parece corto o predecible para firmar/cifrar datos (usa al menos 32 bytes CSPRNG). '
          : ''
      }Reemplázalo por un placeholder descriptivo antes de compartir la plantilla.${clientBundleWarning}`,
      suggestedPlaceholder: 'replace_with_32_byte_random_secret'
    });
  }

  // 7. Exposición de interfaces de red (HOST / BIND_ADDRESS / LISTEN_ADDR) y puerto :80 directo.
  if (GLOBAL_BIND_KEY_PATTERN.test(key) && (cleanValue === '0.0.0.0' || cleanValue === '::' || cleanValue === '[::]')) {
    return createEnvFinding({
      id: `line-${lineNumber}-global-bind`,
      lineNumber,
      key,
      category: 'Exposición de Red',
      severity: SEVERITY.MEDIUM,
      title: 'Enlace de red a todas las interfaces (0.0.0.0)',
      impact: 'Vincular el servicio a 0.0.0.0 expone el socket a todas las interfaces de red locales y externas, exponiendo el puerto a la red física o a contenedores vecinos si no media un firewall estricto.',
      evidenceRedacted: cleanValue,
      mitigation: 'En entornos de desarrollo o detrás de un reverse proxy, enlaza a 127.0.0.1 (localhost). En producción contenerizada, restringe el acceso mediante políticas de red perimetrales.',
      suggestedPlaceholder: '127.0.0.1'
    });
  }

  if (
    /^PORT$/i.test(key) &&
    cleanValue === '80' &&
    (fileContext.isNodeProduction || !fileContext.hasExplicitReverseProxy)
  ) {
    return createEnvFinding({
      id: `line-${lineNumber}-port-80`,
      lineNumber,
      key,
      category: 'Exposición de Red',
      severity: fileContext.isNodeProduction ? SEVERITY.MEDIUM : SEVERITY.LOW,
      title: 'Puerto estándar no cifrado (:80) configurado como escucha directa',
      impact: 'Desplegar servicios sirviendo tráfico directamente en el puerto 80 sin terminación TLS expone la aplicación o requiere privilegios elevados innecesarios.',
      evidenceRedacted: '80',
      mitigation: 'Delega la escucha de los puertos 80/443 a un reverse proxy (Nginx, Caddy, Cloudflare Tunnel) y utiliza puertos no privilegiados de backend (ej. 3000, 8000) en bucle local.',
      suggestedPlaceholder: '3000'
    });
  }

  // 8. Configuraciones operativas inseguras frecuentes en Node/backends.
  if (key.toUpperCase() === 'NODE_TLS_REJECT_UNAUTHORIZED' && cleanValue === '0') {
    return createEnvFinding({
      id: `line-${lineNumber}-tls-disabled`,
      lineNumber,
      key,
      category: 'Configuración TLS',
      severity: SEVERITY.HIGH,
      title: 'Validación de certificados TLS deshabilitada globalmente',
      impact: 'Desactiva la verificación de certificados X.509 en Node.js exponiendo todas las conexiones salientes a ataques MITM.',
      evidenceRedacted: '0',
      mitigation: 'NODE_TLS_REJECT_UNAUTHORIZED=0 desactiva la verificación X.509 y expone todo el tráfico saliente a ataques MITM. Configura NODE_EXTRA_CA_CERTS si usas una CA interna.',
      suggestedPlaceholder: '1'
    });
  }

  if (/^(?:APP_)?DEBUG$/i.test(key) && /^(?:true|1|yes)$/i.test(cleanValue)) {
    return createEnvFinding({
      id: `line-${lineNumber}-debug-enabled`,
      lineNumber,
      key,
      category: 'Exposición de Entorno',
      severity: SEVERITY.MEDIUM,
      title: 'Modo debug activo en configuración',
      impact: 'El modo de depuración habilitado puede filtrar trazas de pila, rutas internas y variables ante excepciones.',
      evidenceRedacted: cleanValue,
      mitigation: 'Asegúrate de forzar DEBUG=false en entornos públicos para evitar volcado de stack traces y variables internas ante errores HTTP 500.',
      suggestedPlaceholder: 'false'
    });
  }

  if (/CORS_ORIGIN/i.test(key) && cleanValue === '*') {
    return createEnvFinding({
      id: `line-${lineNumber}-cors-wildcard`,
      lineNumber,
      key,
      category: 'Política CORS',
      severity: SEVERITY.MEDIUM,
      title: 'Origen CORS comodín (*) permisivo',
      impact: 'Permite que cualquier origen web realice peticiones cross-origin al servicio sin restricción de dominio.',
      evidenceRedacted: '*',
      mitigation: 'Restringe los orígenes permitidos a dominios explícitos (ej. https://app.midominio.com) en endpoints autenticados.',
      suggestedPlaceholder: 'https://app.example.com'
    });
  }

  return null;
}

/**
 * Ejecuta la auditoría completa sobre el contenido .env y construye
 * el archivo `.env.example` sanitizado conservando comentarios y claves legítimas.
 */
export function auditEnvContent(rawContent) {
  const normalizedInput = typeof rawContent === 'string' ? rawContent.replace(/\r\n?/g, '\n') : '';

  if (normalizedInput.trim().length === 0) {
    return {
      findings: [],
      malformedLines: [],
      stats: {
        totalLines: 0,
        analyzedKeys: 0,
        highCount: 0,
        mediumCount: 0,
        lowCount: 0
      },
      flaggedLineSeverity: new Map(),
      sanitizedExample: ''
    };
  }

  const lines = normalizedInput.split('\n');
  const parsedEntries = lines.map((line, index) => parseEnvLine(line, index + 1));
  const fileContext = buildFileAuditContext(parsedEntries);

  const findings = [];
  const malformedLines = [];
  const flaggedLineSeverity = new Map();
  const exampleLines = [];
  let analyzedKeys = 0;

  for (const parsed of parsedEntries) {
    if (parsed.kind === 'blank' || parsed.kind === 'comment') {
      exampleLines.push(parsed.rawLine);
      continue;
    }

    if (parsed.kind === 'malformed') {
      malformedLines.push({
        lineNumber: parsed.lineNumber,
        preview: parsed.rawLine.slice(0, 60)
      });
      exampleLines.push(`# [Formato inválido omitido en línea ${parsed.lineNumber}]`);
      continue;
    }

    analyzedKeys += 1;
    const finding = evaluateAssignmentRisk(parsed, fileContext);

    if (finding) {
      findings.push(finding);
      flaggedLineSeverity.set(parsed.lineNumber, finding.severity);
      const formattedPlaceholder = parsed.quoteChar
        ? `${parsed.quoteChar}${finding.suggestedPlaceholder}${parsed.quoteChar}`
        : finding.suggestedPlaceholder;
      exampleLines.push(`${parsed.exportPrefix}${parsed.key}=${formattedPlaceholder}${parsed.inlineComment}`);
    } else {
      const preservedValue = parsed.quoteChar
        ? `${parsed.quoteChar}${parsed.cleanValue}${parsed.quoteChar}`
        : parsed.cleanValue;
      exampleLines.push(`${parsed.exportPrefix}${parsed.key}=${preservedValue}${parsed.inlineComment}`);
    }
  }

  const highCount = findings.filter((item) => item.severity === SEVERITY.HIGH).length;
  const mediumCount = findings.filter((item) => item.severity === SEVERITY.MEDIUM).length;
  const lowCount = findings.filter((item) => item.severity === SEVERITY.LOW).length;

  return {
    findings,
    malformedLines,
    stats: {
      totalLines: lines.length,
      analyzedKeys,
      highCount,
      mediumCount,
      lowCount
    },
    flaggedLineSeverity,
    sanitizedExample: exampleLines.join('\n')
  };
}

export function buildSanitizedEnvExample(rawContent) {
  return auditEnvContent(rawContent).sanitizedExample;
}
