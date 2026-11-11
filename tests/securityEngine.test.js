import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import { auditEnvContent, buildSanitizedEnvExample, SEVERITY } from '../src/security/envAuditor.js';
import { inspectEndpointUrl } from '../src/security/urlInspector.js';
import { computeSha256Hex, generateSecureSecretHex } from '../src/security/cryptoDigest.js';
import { createInspectorStore } from '../src/state/inspectorStore.js';
import { renderHighlightedEnvHtml } from '../src/ui/envHighlighter.js';
import { escapeHtml } from '../src/ui/domUtils.js';
import { generateSecurityAuditPdf } from '../src/security/pdfReportGenerator.js';

test('auditEnvContent ignora comentarios y líneas vacías pero detecta cadenas críticas, tokens y contraseñas', () => {
  const sampleEnv = [
    '# Configuración principal',
    '',
    'PORT=8080',
    'DATABASE_URL="postgres://prod_admin:Sup3rS3cret!@db.internal:5432/billing"',
    'MONGO_URI=mongodb+srv://svc:Clust3rPass@cluster0.mongodb.net/core',
    'STRIPE_KEY=sk_live_51Nabc1234567890XYZabcdef',
    'GOOGLE_MAPS_KEY=AIzaSyDaGmWKa4JsXZ-HjGw7xY1234567890abc',
    'AUTH_SESSION_JWT=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U',
    'SMTP_PASSWORD=claveEnTextoPlano#2026 # comentario inline',
    'BYPASS_CACHE=false'
  ].join('\n');

  const report = auditEnvContent(sampleEnv);

  // PORT y BYPASS_CACHE no deben producir falsos positivos
  assert.equal(report.stats.analyzedKeys, 8);
  assert.equal(report.findings.length, 6);
  assert.equal(report.stats.highCount, 6);

  // Verifica que el comentario inline no truncó la contraseña con '#'
  const smtpFinding = report.findings.find((item) => item.key === 'SMTP_PASSWORD');
  assert.ok(smtpFinding);
  assert.equal(smtpFinding.severity, SEVERITY.HIGH);

  // El .env.example generado debe ser idempotente (0 hallazgos críticos al re-auditarse)
  const sanitized = buildSanitizedEnvExample(sampleEnv);
  assert.match(sanitized, /^# Configuración principal/m);
  assert.match(sanitized, /^PORT=8080$/m);
  assert.match(sanitized, /^BYPASS_CACHE=false$/m);
  assert.doesNotMatch(sanitized, /Sup3rS3cret!/);
  assert.doesNotMatch(sanitized, /sk_live_51Nabc/);

  const secondPass = auditEnvContent(sanitized);
  assert.equal(secondPass.findings.length, 0);
});

test('inspectEndpointUrl captura errores de formato inválido con new URL() y sugiere https:// si falta esquema', () => {
  const missingScheme = inspectEndpointUrl('api.empresa.io/v1/orders?token=abc');
  assert.equal(missingScheme.isValid, false);
  assert.equal(missingScheme.suggestedHttpsUrl, 'https://api.empresa.io/v1/orders?token=abc');

  const brokenUrl = inspectEndpointUrl('http://[::1]:99999/test');
  assert.equal(brokenUrl.isValid, false);
  assert.equal(brokenUrl.suggestedHttpsUrl, null);
});

test('inspectEndpointUrl detecta HTTP, credenciales embebidas, query params sensibles y puertos críticos', () => {
  const riskyUrl = 'http://admin:root123@db-gateway.internal:27017/metrics?api_key=sk_live_9999888877776666&token=myjwt';
  const result = inspectEndpointUrl(riskyUrl);

  assert.equal(result.isValid, true);
  assert.equal(result.stats.highCount, 4);

  const ids = result.findings.map((item) => item.id);
  assert.ok(ids.includes('insecure-http-protocol'));
  assert.ok(ids.includes('embedded-uri-credentials'));
  assert.ok(ids.includes('sensitive-query-params'));
  assert.ok(ids.includes('exposed-db-port-27017'));

  assert.doesNotMatch(result.sanitizedHref, /root123/);
  assert.doesNotMatch(result.sanitizedHref, /sk_live_9999888877776666/);
});

test('inspectEndpointUrl aprueba un endpoint HTTPS limpio en puerto estándar 443', () => {
  const cleanResult = inspectEndpointUrl('https://api.segura.dev/v2/health?page=1&limit=20');
  assert.equal(cleanResult.isValid, true);
  assert.equal(cleanResult.findings.length, 0);
  assert.equal(cleanResult.anatomy.effectivePort, '443');
});

test('Web Crypto helpers generan SHA-256 determinístico y secretos CSPRNG hexadecimales', async () => {
  const digest = await computeSha256Hex('PORT=3000\n');
  assert.equal(digest?.length, 64);

  const randomSecret = generateSecureSecretHex(32);
  assert.match(randomSecret, /^[0-9a-f]{64}$/);
});

test('createInspectorStore notifica transiciones inmutables y limpia memoria bajo demanda', () => {
  const store = createInspectorStore();
  const events = [];

  const unsubscribe = store.subscribe((nextState, _prevState, reason) => {
    events.push({ reason, activeModule: nextState.activeModule });
  });

  store.setActiveModule('url');
  assert.equal(store.getState().activeModule, 'url');
  assert.ok(Object.isFrozen(store.getState()));

  store.setUrlInspectionResult({
    rawUrl: 'https://example.com',
    inspectionReport: inspectEndpointUrl('https://example.com')
  });
  store.clearUrlSession();
  assert.equal(store.getState().urlSession.rawUrl, '');

  unsubscribe();
  assert.deepEqual(events.map((e) => e.reason), ['module:switch', 'url:inspected', 'url:cleared']);
});

test('renderHighlightedEnvHtml y escapeHtml neutralizan vectores DOM XSS en valores y comentarios', () => {
  const maliciousEnv = 'WEBHOOK_URL="https://evil.test/?q=<img src=x onerror=alert(1)>" # <script>alert(2)</script>\n';
  const report = auditEnvContent(maliciousEnv);
  const html = renderHighlightedEnvHtml(maliciousEnv, report.flaggedLineSeverity);

  assert.doesNotMatch(html, /<img/i);
  assert.doesNotMatch(html, /<script>/i);
  assert.match(html, /&lt;img src=x onerror=alert\(1\)&gt;/);
  assert.ok(html.endsWith(' ')); // Mantiene sincronía de scroll cuando finaliza en salto de línea
  assert.equal(escapeHtml('<svg onload="x">'), '&lt;svg onload=&quot;x&quot;&gt;');
});

test('todos los selectores #id requeridos por los controladores existen en index.html', () => {
  const htmlContent = readFileSync(join(import.meta.dirname, '..', 'index.html'), 'utf8');
  const requiredIds = [
    'inspector-toast',
    'tab-env',
    'tab-url',
    'tab-badge-env',
    'tab-badge-url',
    'panel-env',
    'panel-url',
    'env-raw-input',
    'env-highlight-code',
    'env-highlight-pre',
    'env-line-gutter',
    'env-dropzone',
    'env-file-input',
    'env-source-badge',
    'env-load-sample-btn',
    'env-generate-secret-btn',
    'env-clear-btn',
    'env-summary-strip',
    'env-findings-list',
    'env-example-output',
    'env-copy-example-btn',
    'env-download-example-btn',
    'env-export-pdf-btn',
    'env-copy-hash-btn',
    'env-hash-label',
    'url-inspector-form',
    'url-raw-input',
    'url-clear-btn',
    'url-status-slot',
    'url-anatomy-slot',
    'url-findings-slot'
  ];

  for (const elementId of requiredIds) {
    assert.match(htmlContent, new RegExp(`id="${elementId}"`), `Falta id="${elementId}" en index.html`);
  }
});

test('generateSecurityAuditPdf genera PDF 1.4 válido y redacta secretos en módulos .env y URL', () => {
  const fixedDate = new Date(2026, 10, 11, 16, 45, 30);

  const sampleEnv = [
    'DATABASE_URL="postgres://prod_admin:Sup3rS3cret!@db.internal:5432/billing"',
    'STRIPE_KEY=sk_live_51Nabc1234567890XYZabcdef',
    'PORT=4000'
  ].join('\n');
  const envReport = auditEnvContent(sampleEnv);

  const envPdf = generateSecurityAuditPdf({
    mode: 'env',
    now: fixedDate,
    session: {
      sourceFileName: 'prod.env',
      sha256Fingerprint: 'a'.repeat(64),
      auditReport: envReport,
      sanitizedExample: envReport.sanitizedExample
    }
  });

  assert.equal(envPdf.fileName, 'reporte-seguridad-2026-11-11.pdf');
  assert.equal(envPdf.blob.type, 'application/pdf');
  const envPdfText = Buffer.from(envPdf.pdfBytes).toString('latin1');
  assert.ok(envPdfText.startsWith('%PDF-1.4\n'));
  assert.ok(envPdfText.trimEnd().endsWith('%%EOF'));
  assert.match(envPdfText, /Reporte de Auditor/);
  assert.doesNotMatch(envPdfText, /Sup3rS3cret!/);
  assert.doesNotMatch(envPdfText, /sk_live_51Nabc1234567890XYZabcdef/);

  const riskyUrl = 'http://admin:root123@db-gateway.internal:27017/metrics?api_key=sk_live_9999888877776666';
  const urlReport = inspectEndpointUrl(riskyUrl);
  const urlPdf = generateSecurityAuditPdf({
    mode: 'url',
    now: fixedDate,
    session: {
      rawUrl: riskyUrl,
      inspectionReport: urlReport
    }
  });

  assert.equal(urlPdf.fileName, 'reporte-seguridad-2026-11-11.pdf');
  const urlPdfText = Buffer.from(urlPdf.pdfBytes).toString('latin1');
  assert.ok(urlPdfText.startsWith('%PDF-1.4\n'));
  assert.doesNotMatch(urlPdfText, /root123/);
  assert.doesNotMatch(urlPdfText, /sk_live_9999888877776666/);

  const cleanUrlReport = inspectEndpointUrl('https://api.segura.dev/v2/health');
  const cleanPdf = generateSecurityAuditPdf({
    mode: 'url',
    now: fixedDate,
    session: {
      rawUrl: 'https://api.segura.dev/v2/health',
      inspectionReport: cleanUrlReport
    }
  });
  assert.ok(cleanPdf.pdfBytes.length > 500);
});

