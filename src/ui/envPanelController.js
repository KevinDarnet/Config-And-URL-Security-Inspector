/**
 * Controlador de eventos y renderizado para el Módulo 1:
 * Auditor de archivos .env y Generador reactivo de .env.example.
 */

import { auditEnvContent, SEVERITY } from '../security/envAuditor.js';
import { computeSha256Hex, generateSecureSecretHex } from '../security/cryptoDigest.js';
import { renderHighlightedEnvHtml } from './envHighlighter.js';
import { copyTextToClipboard, downloadPlainTextFile, escapeHtml } from './domUtils.js';

const MAX_ENV_FILE_BYTES = 512 * 1024; // 512 KB evita bloqueo del hilo principal ante archivos binarios grandes.

const SAMPLE_VULNERABLE_ENV = `# Configuración del microservicio de pagos (Staging/Prod)
APP_NAME=checkout-core-api
PORT=4000
LOG_LEVEL=info

# Motores de persistencia y caché
DATABASE_URL="postgres://billing_admin:Pr0d_DbP@ss99!@pg-primary.internal:5432/payments_prod"
MONGODB_URI=mongodb+srv://analytics_svc:M0ng0Clust3rKey@cluster0.corp.mongodb.net/events

# Proveedores externos y criptografía
STRIPE_SECRET_KEY=sk_live_51N9xYzAbCdEfGhIjKlMnOpQrStUvWxYz123456
GOOGLE_GEOCODING_KEY=AIzaSyDaGmWKa4JsXZ-HjGw7xY9876543210abc
SERVICE_MESH_JWT=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJhdXRoLWdhdGV3YXkiLCJyb2xlIjoiYWRtaW4ifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c

# Correo transaccional y banderas operativas
SMTP_PASSWORD=correoClavePlana#2026 # credencial de relay interno
DEBUG=true
CORS_ORIGIN=*
`;

export function mountEnvPanel({ rootElement, store, toast }) {
  const editorTextarea = rootElement.querySelector('#env-raw-input');
  const backdropCode = rootElement.querySelector('#env-highlight-code');
  const backdropPre = rootElement.querySelector('#env-highlight-pre');
  const lineGutter = rootElement.querySelector('#env-line-gutter');
  const dropZone = rootElement.querySelector('#env-dropzone');
  const fileInput = rootElement.querySelector('#env-file-input');
  const sourceBadge = rootElement.querySelector('#env-source-badge');

  const loadSampleBtn = rootElement.querySelector('#env-load-sample-btn');
  const generateSecretBtn = rootElement.querySelector('#env-generate-secret-btn');
  const clearEnvBtn = rootElement.querySelector('#env-clear-btn');

  const summaryContainer = rootElement.querySelector('#env-summary-strip');
  const filterButtons = Array.from(rootElement.querySelectorAll('[data-env-filter]'));
  const findingsList = rootElement.querySelector('#env-findings-list');

  const exampleOutput = rootElement.querySelector('#env-example-output');
  const copyExampleBtn = rootElement.querySelector('#env-copy-example-btn');
  const downloadExampleBtn = rootElement.querySelector('#env-download-example-btn');
  const fingerprintBtn = rootElement.querySelector('#env-copy-hash-btn');
  const fingerprintLabel = rootElement.querySelector('#env-hash-label');

  let fingerprintSequence = 0;
  let copyFeedbackTimer = null;

  function syncEditorScroll() {
    backdropPre.scrollTop = editorTextarea.scrollTop;
    backdropPre.scrollLeft = editorTextarea.scrollLeft;
    lineGutter.scrollTop = editorTextarea.scrollTop;
  }

  function renderLineNumbers(rawText, flaggedLineSeverity = new Map()) {
    const lineCount = rawText ? rawText.replace(/\r\n?/g, '\n').split('\n').length : 1;
    const items = [];

    for (let lineNum = 1; lineNum <= lineCount; lineNum += 1) {
      const severity = flaggedLineSeverity.get(lineNum);
      const colorClass =
        severity === SEVERITY.HIGH
          ? 'text-rose-400 font-semibold'
          : severity === SEVERITY.MEDIUM
            ? 'text-amber-400 font-semibold'
            : 'text-slate-600';
      items.push(`<span class="block ${colorClass}">${lineNum}</span>`);
    }

    lineGutter.innerHTML = items.join('');
  }

  async function runInspection(rawText, sourceFileName = null) {
    const currentSeq = ++fingerprintSequence;

    try {
      const auditReport = auditEnvContent(rawText);
      store.setEnvInspectionResult({
        rawText,
        sourceFileName,
        auditReport,
        sanitizedExample: auditReport.sanitizedExample,
        sha256Fingerprint: null
      });

      const digestHex = await computeSha256Hex(rawText);
      if (currentSeq === fingerprintSequence) {
        store.setEnvFingerprint(digestHex);
      }
    } catch (inspectionError) {
      console.error('[EnvPanel] Error inesperado durante la auditoría de .env:', inspectionError);
      toast.show('Error al analizar el contenido .env. Revisa la consola para detalles.', 'error');
    }
  }

  function handleLocalFile(file) {
    if (!file) {
      return;
    }

    if (file.size > MAX_ENV_FILE_BYTES) {
      console.warn(`[EnvPanel] Archivo rechazado por tamaño excesivo (${file.size} bytes):`, file.name);
      toast.show('Archivo demasiado grande (máximo 512 KB para archivos .env).', 'warning');
      return;
    }

    const reader = new FileReader();

    reader.onerror = () => {
      console.error('[EnvPanel] Fallo de lectura en FileReader:', reader.error);
      toast.show('No se pudo leer el archivo seleccionado.', 'error');
    };

    reader.onload = () => {
      const content = typeof reader.result === 'string' ? reader.result : '';
      // Un byte nulo indica archivo binario cargado por accidente.
      if (content.includes('\u0000')) {
        console.warn('[EnvPanel] Se detectaron bytes nulos; archivo binario descartado:', file.name);
        toast.show('El archivo parece binario. Selecciona un archivo .env en texto plano.', 'error');
        return;
      }

      editorTextarea.value = content;
      runInspection(content, file.name);
      toast.show(`Archivo "${file.name}" cargado en memoria local.`, 'success');
    };

    reader.readAsText(file, 'utf-8');
  }

  function focusEditorLine(targetLineNumber) {
    const lines = editorTextarea.value.replace(/\r\n?/g, '\n').split('\n');
    const clampedLine = Math.max(1, Math.min(targetLineNumber, lines.length));
    let startOffset = 0;

    for (let idx = 0; idx < clampedLine - 1; idx += 1) {
      startOffset += lines[idx].length + 1;
    }

    const endOffset = startOffset + (lines[clampedLine - 1]?.length ?? 0);
    editorTextarea.focus();
    editorTextarea.setSelectionRange(startOffset, endOffset);

    const approximateLineHeightPx = 22.4;
    editorTextarea.scrollTop = Math.max(0, (clampedLine - 3) * approximateLineHeightPx);
    syncEditorScroll();
  }

  function renderSummaryStrip(auditReport) {
    if (!auditReport || auditReport.stats.analyzedKeys === 0) {
      summaryContainer.innerHTML = `
        <div class="flex flex-wrap items-center justify-between gap-2 rounded-xl bg-slate-950/70 border border-slate-800/90 px-3.5 py-2.5 text-xs text-slate-400">
          <span>Esperando variables de entorno para auditar en cliente…</span>
          <span class="inline-flex items-center gap-1.5 font-mono text-[11px] text-cyan-400">
            <span class="h-1.5 w-1.5 rounded-full bg-cyan-400"></span>0 bytes enviados a red
          </span>
        </div>
      `;
      return;
    }

    const { analyzedKeys, highCount, mediumCount } = auditReport.stats;
    const isClean = highCount === 0 && mediumCount === 0;

    const statusBadge = isClean
      ? `<span class="inline-flex items-center gap-1.5 rounded-full bg-emerald-500/15 border border-emerald-500/30 px-2.5 py-1 text-xs font-semibold text-emerald-300">
           <span class="h-1.5 w-1.5 rounded-full bg-emerald-400"></span>SEGURO · SIN FUGAS
         </span>`
      : highCount > 0
        ? `<span class="inline-flex items-center gap-1.5 rounded-full bg-rose-500/15 border border-rose-500/35 px-2.5 py-1 text-xs font-semibold text-rose-300">
             <span class="h-1.5 w-1.5 rounded-full bg-rose-500"></span>RIESGO CRÍTICO DETECTADO
           </span>`
        : `<span class="inline-flex items-center gap-1.5 rounded-full bg-amber-500/15 border border-amber-500/35 px-2.5 py-1 text-xs font-semibold text-amber-300">
             <span class="h-1.5 w-1.5 rounded-full bg-amber-400"></span>REVISIÓN RECOMENDADA
           </span>`;

    summaryContainer.innerHTML = `
      <div class="flex flex-wrap items-center justify-between gap-3 rounded-xl bg-slate-950/80 border border-slate-800 px-3.5 py-3">
        <div class="flex flex-wrap items-center gap-2">
          ${statusBadge}
          <span class="rounded-lg bg-slate-800/90 border border-slate-700/60 px-2.5 py-1 font-mono text-xs text-slate-300">
            ${analyzedKeys} ${analyzedKeys === 1 ? 'clave' : 'claves'}
          </span>
        </div>
        <div class="flex items-center gap-2 font-mono text-xs">
          <span class="rounded-md bg-rose-500/15 border border-rose-500/30 px-2 py-0.5 text-rose-300">
            ALTA: ${highCount}
          </span>
          <span class="rounded-md bg-amber-500/15 border border-amber-500/30 px-2 py-0.5 text-amber-300">
            MEDIA: ${mediumCount}
          </span>
        </div>
      </div>
    `;
  }

  function renderFindingsList(auditReport, severityFilter) {
    if (!auditReport || auditReport.stats.analyzedKeys === 0) {
      findingsList.innerHTML = `
        <div class="rounded-xl border border-dashed border-slate-800 bg-slate-950/40 p-6 text-center">
          <p class="text-sm font-medium text-slate-300">Ningún hallazgo activo</p>
          <p class="mt-1 text-xs text-slate-500">
            Pega el contenido de tu archivo <code class="font-mono text-slate-400">.env</code>, arrástralo al recuadro o carga el ejemplo de prueba.
          </p>
        </div>
      `;
      return;
    }

    const filtered =
      severityFilter === 'ALL'
        ? auditReport.findings
        : auditReport.findings.filter((item) => item.severity === severityFilter);

    if (auditReport.findings.length === 0) {
      findingsList.innerHTML = `
        <div class="rounded-xl border border-emerald-500/30 bg-emerald-500/10 p-5">
          <div class="flex items-center gap-2.5">
            <span class="h-2.5 w-2.5 rounded-full bg-emerald-400"></span>
            <h4 class="text-sm font-semibold text-emerald-300">Configuración libre de secretos expuestos</h4>
          </div>
          <p class="mt-1.5 text-xs leading-relaxed text-emerald-200/80">
            Se inspeccionaron ${auditReport.stats.analyzedKeys} variables ignorando comentarios y líneas en blanco sin detectar credenciales en texto plano, tokens firmados ni cadenas de conexión críticas.
          </p>
        </div>
      `;
      return;
    }

    if (filtered.length === 0) {
      findingsList.innerHTML = `
        <div class="rounded-xl border border-slate-800 bg-slate-950/50 p-5 text-center text-xs text-slate-400">
          No existen alertas con severidad <strong class="font-mono text-slate-200">${escapeHtml(severityFilter)}</strong> en esta auditoría.
        </div>
      `;
      return;
    }

    findingsList.innerHTML = filtered
      .map((finding) => {
        const isHigh = finding.severity === SEVERITY.HIGH;
        const cardBorder = isHigh
          ? 'border-rose-500/30 hover:border-rose-500/50'
          : 'border-amber-500/30 hover:border-amber-500/50';
        const severityBadge = isHigh
          ? 'bg-rose-500/15 text-rose-300 border-rose-500/35'
          : 'bg-amber-500/15 text-amber-300 border-amber-500/35';

        return `
          <article class="rounded-xl bg-slate-950/75 border ${cardBorder} p-4 transition-colors">
            <div class="flex flex-wrap items-start justify-between gap-2">
              <div class="flex flex-wrap items-center gap-2">
                <span class="inline-flex items-center rounded-md border px-2 py-0.5 font-mono text-[11px] font-bold tracking-wide ${severityBadge}">
                  ${escapeHtml(finding.severity)}
                </span>
                <span class="rounded-md bg-slate-800/90 border border-slate-700/60 px-2 py-0.5 text-[11px] font-medium text-slate-300">
                  ${escapeHtml(finding.category)}
                </span>
              </div>
              <button
                type="button"
                data-jump-line="${finding.lineNumber}"
                class="min-h-[34px] rounded-lg bg-slate-800/80 hover:bg-slate-800 border border-slate-700/70 px-2.5 py-1 font-mono text-xs text-cyan-300 transition-colors"
                title="Ubicar cursor en la línea ${finding.lineNumber}"
              >
                Línea ${finding.lineNumber} →
              </button>
            </div>

            <h4 class="mt-2.5 text-sm font-semibold text-slate-100">${escapeHtml(finding.title)}</h4>

            <div class="mt-2 flex flex-wrap items-center gap-x-2 gap-y-1 rounded-lg bg-slate-900/90 border border-slate-800 px-3 py-2 font-mono text-xs">
              <span class="text-cyan-300">${escapeHtml(finding.key)}</span>
              <span class="text-slate-600">=</span>
              <span class="break-all text-slate-300">${escapeHtml(finding.maskedPreview)}</span>
            </div>

            <p class="mt-2.5 text-xs leading-relaxed text-slate-400">
              <strong class="text-slate-200">Mitigación:</strong> ${escapeHtml(finding.remediation)}
            </p>
          </article>
        `;
      })
      .join('');
  }

  function renderFromState(envSession) {
    const { rawText, sourceFileName, severityFilter, sha256Fingerprint, auditReport, sanitizedExample } = envSession;
    const flaggedMap = auditReport?.flaggedLineSeverity || new Map();

    if (editorTextarea.value !== rawText) {
      editorTextarea.value = rawText;
    }

    backdropCode.innerHTML = renderHighlightedEnvHtml(rawText, flaggedMap);
    renderLineNumbers(rawText, flaggedMap);
    syncEditorScroll();

    sourceBadge.textContent = sourceFileName ? `Archivo: ${sourceFileName}` : 'Entrada directa en memoria';

    for (const btn of filterButtons) {
      const isSelected = btn.dataset.envFilter === severityFilter;
      btn.setAttribute('aria-pressed', String(isSelected));
      btn.className = isSelected
        ? 'min-h-[44px] rounded-lg bg-cyan-500/15 border border-cyan-400/40 px-3.5 py-2 text-xs font-semibold text-cyan-300 transition-colors'
        : 'min-h-[44px] rounded-lg bg-slate-900/80 hover:bg-slate-800 border border-slate-800 px-3.5 py-2 text-xs font-medium text-slate-400 hover:text-slate-200 transition-colors';
    }

    renderSummaryStrip(auditReport);
    renderFindingsList(auditReport, severityFilter);

    exampleOutput.textContent =
      sanitizedExample || '# El archivo .env.example sanitizado se generará automáticamente aquí…';
    copyExampleBtn.disabled = !sanitizedExample;
    downloadExampleBtn.disabled = !sanitizedExample;

    if (sha256Fingerprint) {
      fingerprintLabel.textContent = `SHA-256: ${sha256Fingerprint.slice(0, 12)}…`;
      fingerprintBtn.disabled = false;
      fingerprintBtn.dataset.fullHash = sha256Fingerprint;
    } else {
      fingerprintLabel.textContent = 'SHA-256: —';
      fingerprintBtn.disabled = true;
      delete fingerprintBtn.dataset.fullHash;
    }
  }

  // Eventos del editor y sincronización de scroll
  editorTextarea.addEventListener('input', (event) => {
    runInspection(event.target.value, null);
  });

  editorTextarea.addEventListener('scroll', syncEditorScroll, { passive: true });

  // Carga mediante selector de archivo y Drag & Drop
  fileInput.addEventListener('change', (event) => {
    const selectedFile = event.target.files?.[0];
    handleLocalFile(selectedFile);
    fileInput.value = '';
  });

  ['dragenter', 'dragover'].forEach((eventName) => {
    dropZone.addEventListener(eventName, (event) => {
      event.preventDefault();
      dropZone.classList.add('border-cyan-400/70', 'bg-cyan-500/10');
    });
  });

  ['dragleave', 'drop'].forEach((eventName) => {
    dropZone.addEventListener(eventName, (event) => {
      event.preventDefault();
      dropZone.classList.remove('border-cyan-400/70', 'bg-cyan-500/10');
    });
  });

  dropZone.addEventListener('drop', (event) => {
    const droppedFile = event.dataTransfer?.files?.[0];
    handleLocalFile(droppedFile);
  });

  // Botones de acción rápida
  loadSampleBtn.addEventListener('click', () => {
    editorTextarea.value = SAMPLE_VULNERABLE_ENV;
    runInspection(SAMPLE_VULNERABLE_ENV, 'muestra-staging.env');
    toast.show('Muestra de auditoría cargada localmente.', 'info');
  });

  generateSecretBtn.addEventListener('click', async () => {
    try {
      const freshHexSecret = generateSecureSecretHex(32);
      const copied = await copyTextToClipboard(freshHexSecret);
      if (copied) {
        toast.show('Secreto CSPRNG de 256 bits generado y copiado al portapapeles.', 'success');
      } else {
        toast.show(`Secreto generado: ${freshHexSecret.slice(0, 16)}…`, 'info');
      }
    } catch (cryptoError) {
      console.error('[EnvPanel] Fallo al generar secreto CSPRNG:', cryptoError);
      toast.show('Web Crypto no está disponible en este entorno.', 'error');
    }
  });

  clearEnvBtn.addEventListener('click', () => {
    fingerprintSequence += 1;
    store.clearEnvSession();
    toast.show('Memoria del auditor .env vaciada.', 'info');
  });

  // Filtros de severidad y salto a línea
  filterButtons.forEach((btn) => {
    btn.addEventListener('click', () => {
      store.setEnvSeverityFilter(btn.dataset.envFilter);
    });
  });

  findingsList.addEventListener('click', (event) => {
    const jumpTrigger = event.target.closest('[data-jump-line]');
    if (!jumpTrigger) {
      return;
    }
    const lineNum = Number(jumpTrigger.dataset.jumpLine);
    if (Number.isInteger(lineNum) && lineNum > 0) {
      focusEditorLine(lineNum);
    }
  });

  // Acciones de exportación y copiado de .env.example
  copyExampleBtn.addEventListener('click', async () => {
    const sanitizedText = store.getState().envSession.sanitizedExample;
    if (!sanitizedText) {
      return;
    }

    const copied = await copyTextToClipboard(sanitizedText);
    if (!copied) {
      toast.show('No fue posible copiar automáticamente. Selecciona el bloque manualmente.', 'warning');
      return;
    }

    const labelSpan = copyExampleBtn.querySelector('[data-copy-label]');
    if (labelSpan) {
      labelSpan.textContent = '¡Copiado!';
    }
    copyExampleBtn.classList.add('border-emerald-500/50', 'text-emerald-300');

    if (copyFeedbackTimer) {
      clearTimeout(copyFeedbackTimer);
    }
    copyFeedbackTimer = setTimeout(() => {
      if (labelSpan) {
        labelSpan.textContent = 'Copiar .env.example';
      }
      copyExampleBtn.classList.remove('border-emerald-500/50', 'text-emerald-300');
    }, 2200);

    toast.show('Plantilla .env.example copiada al portapapeles.', 'success');
  });

  downloadExampleBtn.addEventListener('click', () => {
    const sanitizedText = store.getState().envSession.sanitizedExample;
    if (!sanitizedText) {
      return;
    }
    const downloaded = downloadPlainTextFile('.env.example', `${sanitizedText}\n`);
    if (downloaded) {
      toast.show('Descargando archivo .env.example sanitizado.', 'success');
    }
  });

  fingerprintBtn.addEventListener('click', async () => {
    const fullHash = fingerprintBtn.dataset.fullHash;
    if (!fullHash) {
      return;
    }
    const copied = await copyTextToClipboard(fullHash);
    if (copied) {
      toast.show('Hash de integridad SHA-256 copiado.', 'success');
    }
  });

  // Suscripción reactiva al estado
  store.subscribe((nextState, prevState) => {
    if (nextState.envSession !== prevState.envSession) {
      renderFromState(nextState.envSession);
    }
  });

  renderFromState(store.getState().envSession);
}
