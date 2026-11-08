/**
 * Analizador estático puro de URLs y endpoints mediante `new URL()`.
 * Ejecuta reglas de seguridad 100% en memoria local sin emitir peticiones de red (cero fugas DNS/CORS).
 */

import { SEVERITY } from './envAuditor.js';

const SENSITIVE_QUERY_KEYS = new Set([
  'token',
  'access_token',
  'refresh_token',
  'id_token',
  'api_token',
  'auth_token',
  'reset_token',
  'csrf_token',
  'key',
  'api_key',
  'apikey',
  'private_key',
  'access_key',
  'secret_key',
  'auth',
  'authorization',
  'secret',
  'client_secret',
  'app_secret',
  'webhook_secret',
  'jwt',
  'password',
  'passwd',
  'pwd',
  'pass',
  'passphrase',
  'session',
  'session_id',
  'sessionid',
  'sid',
  'sig',
  'signature',
  'x-amz-signature',
  'bearer',
  'credential',
  'credentials'
]);

const SENSITIVE_KEY_SUBSTRING = /(?:token|secret|passwd|password|apikey|api_key|private_key|auth_key|client_secret)/i;
const VALUE_LOOKS_LIKE_TOKEN = /^(?:eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.|(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{12,}|AIza[0-9A-Za-z_-]{30,}|gh[pousr]_[A-Za-z0-9]{20,})/;

const DATABASE_AND_INFRA_PORTS = new Map([
  ['27017', 'MongoDB (mongod)'],
  ['27018', 'MongoDB Shard'],
  ['5432', 'PostgreSQL'],
  ['3306', 'MySQL / MariaDB'],
  ['6379', 'Redis'],
  ['9200', 'Elasticsearch HTTP'],
  ['9300', 'Elasticsearch Transport'],
  ['5672', 'RabbitMQ AMQP'],
  ['15672', 'RabbitMQ Management UI'],
  ['1433', 'Microsoft SQL Server'],
  ['9042', 'Apache Cassandra'],
  ['2379', 'etcd API']
]);

const DEV_AND_APP_PORTS = new Map([
  ['3000', 'Servidor Node.js / Express / Next.js Dev'],
  ['3001', 'Servidor secundario de desarrollo'],
  ['4000', 'GraphQL / Phoenix Dev'],
  ['4200', 'Angular CLI Dev Server'],
  ['5000', 'Flask / Gunicorn / ASP.NET local'],
  ['5173', 'Vite Dev Server'],
  ['8000', 'Django / FastAPI / Uvicorn'],
  ['8080', 'HTTP alternativo / Tomcat / Proxy sin TLS'],
  ['8081', 'Servicio HTTP secundario'],
  ['8443', 'HTTPS en puerto alternativo no estándar'],
  ['8888', 'Jupyter Notebook / Proxy administrativo'],
  ['9000', 'PHP-FPM / MinIO / SonarQube']
]);

const DEFAULT_SCHEME_PORTS = Object.freeze({
  'http:': '80',
  'https:': '443',
  'ws:': '80',
  'wss:': '443',
  'ftp:': '21'
});

function isLoopbackHost(hostname) {
  const normalized = String(hostname || '').toLowerCase();
  return (
    normalized === 'localhost' ||
    normalized === '127.0.0.1' ||
    normalized === '[::1]' ||
    normalized.endsWith('.localhost')
  );
}

function redactUrlCredentialsAndQuery(parsedUrl, sensitiveParamNames) {
  try {
    const clone = new URL(parsedUrl.href);
    if (clone.username) {
      clone.username = '<redacted_user>';
    }
    if (clone.password) {
      clone.password = '<redacted_pass>';
    }
    for (const key of sensitiveParamNames) {
      if (clone.searchParams.has(key)) {
        clone.searchParams.set(key, '<REDACTED>');
      }
    }
    return clone.href;
  } catch {
    return parsedUrl.origin || '(URL sanitizada no disponible)';
  }
}

function inspectProtocol(parsedUrl) {
  const protocol = parsedUrl.protocol.toLowerCase();
  const loopback = isLoopbackHost(parsedUrl.hostname);

  if (protocol === 'https:' || protocol === 'wss:') {
    return null;
  }

  if (protocol === 'http:') {
    return {
      id: 'insecure-http-protocol',
      category: 'Seguridad de Transporte',
      severity: loopback ? SEVERITY.MEDIUM : SEVERITY.HIGH,
      title: loopback
        ? 'Uso de HTTP sin cifrar sobre interfaz local (loopback)'
        : 'Protocolo HTTP inseguro: tráfico expuesto en texto plano',
      evidence: `${protocol}//${parsedUrl.hostname}`,
      description: loopback
        ? 'Aunque el tráfico en localhost no atraviesa la red física, impide probar cookies con atributo Secure/__Host- y difiere del comportamiento TLS de producción.'
        : 'Cualquier nodo intermedio (Wi-Fi pública, ISP, router corporativo) puede interceptar o modificar cabeceras, tokens y payloads mediante ataques Man-in-the-Middle (MITM).',
      mitigation: loopback
        ? 'Para flujos de autenticación local utiliza certificados de desarrollo (mkcert) o asegúrate de forzar HTTPS mediante variables de entorno en staging y producción.'
        : 'Migra el endpoint a HTTPS (TLS 1.2/1.3), redirige el puerto 80 al 443 con código 308 y publica la cabecera Strict-Transport-Security: max-age=63072000; includeSubDomains; preload.'
    };
  }

  if (protocol === 'ws:') {
    return {
      id: 'insecure-ws-protocol',
      category: 'Seguridad de Transporte',
      severity: loopback ? SEVERITY.MEDIUM : SEVERITY.HIGH,
      title: 'Canal WebSocket sin cifrado TLS (ws://)',
      evidence: `ws://${parsedUrl.hostname}`,
      description: 'Los frames bidireccionales del WebSocket y el handshake inicial viajan en claro, permitiendo lectura o inyección de mensajes en tránsito.',
      mitigation: 'Actualiza el esquema a wss:// sobre TLS en el puerto 443 detrás de tu proxy inverso o balanceador.'
    };
  }

  if (protocol === 'javascript:' || protocol === 'data:' || protocol === 'vbscript:') {
    return {
      id: 'dangerous-pseudo-scheme',
      category: 'Inyección / XSS',
      severity: SEVERITY.HIGH,
      title: `Esquema ejecutable peligroso detectado (${protocol})`,
      evidence: protocol,
      description: 'Asignar esquemas ejecutables en enlaces dinámicos, redirecciones o iframes permite ejecución arbitraria de código JavaScript (DOM XSS).',
      mitigation: 'Valida estrictamente que las URLs externas pertenezcan a una lista blanca de esquemas permitidos: únicamente https: (o http: controlado).'
    };
  }

  return {
    id: 'non-https-protocol',
    category: 'Protocolo No Estándar Web',
    severity: SEVERITY.HIGH,
    title: `Esquema "${protocol.replace(':', '')}" inapropiado para consumo directo en cliente`,
    evidence: protocol,
    description: 'El protocolo indicado corresponde a transferencia heredada o acceso directo a servicios internos sin garantías estándar de transporte HTTPS.',
    mitigation: 'Encapsula el recurso detrás de una API REST/GraphQL sobre HTTPS y restringe el protocolo nativo a la red privada del backend.'
  };
}

function inspectEmbeddedCredentials(parsedUrl) {
  const hasUsername = parsedUrl.username.length > 0;
  const hasPassword = parsedUrl.password.length > 0;

  if (!hasUsername && !hasPassword) {
    return null;
  }

  const safeUser = decodeURIComponent(parsedUrl.username || '(vacío)');
  const evidence = hasPassword
    ? `${safeUser}:••••••••@${parsedUrl.hostname}`
    : `${safeUser}@${parsedUrl.hostname}`;

  return {
    id: 'embedded-uri-credentials',
    category: 'Credenciales en URI',
    severity: SEVERITY.HIGH,
    title: hasPassword
      ? 'Usuario y contraseña embebidos directamente en la URI'
      : 'Identificador de usuario embebido en la autoridad de la URI',
    evidence,
    description: 'El estándar RFC 3986 (§3.2.1) depreca el formato user:password@host: las credenciales quedan registradas en logs de proxies, historial y listas de procesos, además de ser bloqueadas por fetch() en navegadores modernos.',
    mitigation: 'Elimina las credenciales de la URL y transmítelas mediante la cabecera HTTP Authorization (Bearer / Basic sobre TLS) o autenticación mutua (mTLS).'
  };
}

function inspectQueryAndFragmentSecrets(parsedUrl) {
  const findings = [];
  const detectedSensitiveKeys = [];
  const disguisedTokenKeys = [];

  for (const [rawKey, rawValue] of parsedUrl.searchParams.entries()) {
    const normalizedKey = rawKey.trim().toLowerCase();
    const keyMatchesDictionary =
      SENSITIVE_QUERY_KEYS.has(normalizedKey) || SENSITIVE_KEY_SUBSTRING.test(normalizedKey);
    const valueMatchesTokenSignature = VALUE_LOOKS_LIKE_TOKEN.test(rawValue.trim());

    if (keyMatchesDictionary) {
      detectedSensitiveKeys.push(rawKey);
    } else if (valueMatchesTokenSignature) {
      disguisedTokenKeys.push(rawKey);
    }
  }

  const allFlaggedKeys = [...new Set([...detectedSensitiveKeys, ...disguisedTokenKeys])];

  if (allFlaggedKeys.length > 0) {
    const formattedParams = allFlaggedKeys.map((key) => `?${key}=••••`).join(', ');
    findings.push({
      id: 'sensitive-query-params',
      category: 'Fuga en Query String',
      severity: SEVERITY.HIGH,
      title: `Parámetros sensibles expuestos en la URL (${allFlaggedKeys.join(', ')})`,
      evidence: formattedParams,
      description: 'Los parámetros de consulta viajan íntegros en la línea de petición HTTP: quedan almacenados en claro en access logs de servidores/CDNs (Nginx, CloudFront), telemetría APM, historial del navegador y se filtran a dominios externos mediante la cabecera Referer.',
      mitigation: 'Mueve secretos y tokens a la cabecera Authorization: Bearer <token> o cookies HttpOnly; Secure; SameSite=Strict. Si debes usar enlaces firmados temporales, aplica expiración de segundos, un solo uso y configura Referrer-Policy: no-referrer.'
    });
  }

  // Inspección adicional del fragmento (#access_token=...) típico del flujo OAuth Implicit deprecado.
  if (parsedUrl.hash.length > 1) {
    const rawFragment = parsedUrl.hash.slice(1);
    if (/(?:^|&)(?:access_token|id_token|token|secret|key)=/i.test(rawFragment)) {
      findings.push({
        id: 'sensitive-hash-fragment',
        category: 'Fragmento URI (#)',
        severity: SEVERITY.MEDIUM,
        title: 'Token detectado en el fragmento hash (#) de la URL',
        evidence: '#...=<REDACTED>',
        description: 'Aunque el navegador no envía el fragmento # al servidor, permanece accesible para cualquier script de terceros en la página (riesgo ante XSS) y en el historial local (flujo OAuth Implicit deprecado por RFC 9700).',
        mitigation: 'Migra a OAuth 2.0 Authorization Code Flow con PKCE intercambiando el código por tokens mediante petición POST fuera de la URL.'
      });
    }
  }

  return { findings, flaggedParamKeys: allFlaggedKeys };
}

function inspectPortExposure(parsedUrl, rawInput) {
  // new URL() normaliza puertos por defecto (:80 en http, :443 en https) a cadena vacía,
  // por lo que extraemos también si el usuario escribió explícitamente un puerto en la autoridad.
  let explicitPort = parsedUrl.port;

  if (!explicitPort) {
    const explicitDefaultMatch = rawInput.match(/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\/(?:[^/?#@]+@)?(?:\[[^\]]+\]|[^:/?#]+):(\d+)(?:[/?#]|$)/);
    if (explicitDefaultMatch) {
      const candidatePort = explicitDefaultMatch[1];
      const schemeDefault = DEFAULT_SCHEME_PORTS[parsedUrl.protocol.toLowerCase()];
      if (candidatePort !== schemeDefault) {
        explicitPort = candidatePort;
      }
    }
  }

  if (!explicitPort) {
    return null;
  }

  if (DATABASE_AND_INFRA_PORTS.has(explicitPort)) {
    const serviceName = DATABASE_AND_INFRA_PORTS.get(explicitPort);
    return {
      id: `exposed-db-port-${explicitPort}`,
      category: 'Superficie de Red / Puerto Crítico',
      severity: SEVERITY.HIGH,
      title: `Puerto de infraestructura de datos expuesto (:${explicitPort} — ${serviceName})`,
      evidence: `${parsedUrl.hostname}:${explicitPort}`,
      description: `El puerto ${explicitPort} está asociado a ${serviceName}. Exponer motores de datos o paneles internos directamente en URLs accesibles incrementa el riesgo de fuerza bruta, explotación de CVEs de protocolo y SSRF.`,
      mitigation: `Restringe el puerto ${explicitPort} exclusivamente a la subred privada/VPC (bind a 127.0.0.1 o Security Group interno) y consume los datos únicamente a través de una capa de API autenticada en :443.`
    };
  }

  if (DEV_AND_APP_PORTS.has(explicitPort)) {
    const runtimeLabel = DEV_AND_APP_PORTS.get(explicitPort);
    return {
      id: `dev-app-port-${explicitPort}`,
      category: 'Puerto de Desarrollo / App',
      severity: SEVERITY.MEDIUM,
      title: `Puerto no estándar de desarrollo o backend directo (:${explicitPort})`,
      evidence: `${parsedUrl.hostname}:${explicitPort} (${runtimeLabel})`,
      description: `Conectar clientes directamente al puerto ${explicitPort} suele omitir la capa de proxy inverso endurecida (WAF, rate-limiting, cabeceras de seguridad y terminación TLS centralizada) y revela la tecnología subyacente.`,
      mitigation: 'Publica el servicio detrás de un Reverse Proxy o API Gateway (Nginx, Caddy, Envoy, Cloudflare) escuchando en el puerto estándar 443 con TLS y cierra el acceso externo directo al puerto de aplicación.'
    };
  }

  return {
    id: `custom-nonstandard-port-${explicitPort}`,
    category: 'Puerto No Estándar',
    severity: SEVERITY.MEDIUM,
    title: `Uso de puerto TCP no estándar explícito (:${explicitPort})`,
    evidence: `${parsedUrl.hostname}:${explicitPort}`,
    description: 'Los puertos fuera de 443/80 pueden ser bloqueados por firewalls corporativos estrictos y frecuentemente corresponden a servicios auxiliares sin políticas de endurecimiento perimetral.',
    mitigation: 'Verifica que el servicio requiera exponer este puerto; preferiblemente enrútalo mediante subdominios o rutas bajo HTTPS en el puerto 443.'
  };
}

/**
 * Analiza estáticamente una URL o endpoint usando `new URL()` con control defensivo de errores.
 */
export function inspectEndpointUrl(rawInput) {
  const trimmedInput = typeof rawInput === 'string' ? rawInput.trim() : '';

  if (trimmedInput.length === 0) {
    return {
      isValid: false,
      isEmpty: true,
      errorMessage: null,
      suggestedHttpsUrl: null,
      findings: [],
      anatomy: null
    };
  }

  let parsedUrl;
  try {
    parsedUrl = new URL(trimmedInput);
  } catch (urlParseError) {
    console.warn('[UrlInspector] Formato inválido rechazado por new URL():', {
      inputPreview: trimmedInput.slice(0, 80),
      reason: urlParseError.message
    });

    const missingScheme = !/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(trimmedInput) && /^[\w.-]+(?::\d+)?(?:\/|$|\?)/.test(trimmedInput);

    return {
      isValid: false,
      isEmpty: false,
      errorMessage: missingScheme
        ? 'La URL no incluye esquema de protocolo (ej. https:// o http://), requerido por el parser estándar WHATWG new URL().'
        : 'La sintaxis de la URL es inválida. Verifica el protocolo, caracteres no codificados en la autoridad o el número de puerto (1–65535).',
      suggestedHttpsUrl: missingScheme ? `https://${trimmedInput}` : null,
      suggestedHttpUrl: missingScheme ? `http://${trimmedInput}` : null,
      findings: [],
      anatomy: null
    };
  }

  const findings = [];

  const protocolFinding = inspectProtocol(parsedUrl);
  if (protocolFinding) {
    findings.push(protocolFinding);
  }

  const credentialsFinding = inspectEmbeddedCredentials(parsedUrl);
  if (credentialsFinding) {
    findings.push(credentialsFinding);
  }

  const { findings: queryFindings, flaggedParamKeys } = inspectQueryAndFragmentSecrets(parsedUrl);
  findings.push(...queryFindings);

  const portFinding = inspectPortExposure(parsedUrl, trimmedInput);
  if (portFinding) {
    findings.push(portFinding);
  }

  const protocolLower = parsedUrl.protocol.toLowerCase();
  const effectivePort = parsedUrl.port || DEFAULT_SCHEME_PORTS[protocolLower] || 'N/A';
  const highCount = findings.filter((item) => item.severity === SEVERITY.HIGH).length;
  const mediumCount = findings.filter((item) => item.severity === SEVERITY.MEDIUM).length;

  const queryEntries = Array.from(parsedUrl.searchParams.entries()).map(([key, value]) => {
    const isSensitive = flaggedParamKeys.includes(key);
    return {
      key,
      displayValue: isSensitive ? '•••••••• (oculto)' : value || '(vacío)',
      isSensitive
    };
  });

  return {
    isValid: true,
    isEmpty: false,
    errorMessage: null,
    suggestedHttpsUrl: null,
    sanitizedHref: redactUrlCredentialsAndQuery(parsedUrl, flaggedParamKeys),
    stats: {
      highCount,
      mediumCount,
      totalFindings: findings.length
    },
    anatomy: {
      protocol: protocolLower.replace(':', '').toUpperCase(),
      hostname: parsedUrl.hostname || '(sin host)',
      explicitPort: parsedUrl.port || null,
      effectivePort,
      pathname: parsedUrl.pathname || '/',
      queryCount: queryEntries.length,
      queryEntries,
      hasCredentials: Boolean(parsedUrl.username || parsedUrl.password),
      hasFragment: parsedUrl.hash.length > 1
    },
    findings
  };
}
