/**
 * Controlador de eventos y renderizado para el Módulo 2:
 * Analizador Estático de URLs / Endpoints mediante `new URL()`.
 */

import { SEVERITY } from '../security/envAuditor.js';
import { inspectEndpointUrl } from '../security/urlInspector.js';
import { copyTextToClipboard, escapeHtml } from './domUtils.js';

const PRESET_ENDPOINTS = Object.freeze({
  'http-query-leak': 'http://api.billing-staging.internal:8080/v1/checkout/callback?token=eyJhbGciOiJIUzI1NiJ9.eyJ1aWQiOjg0fQ.sig&api_key=sk_live_9876543210abcdef',
  'uri-creds-db': 'http://root:Sup3rAdmin2026@mongo-node01.corp.net:27017/users_prod?auth=legacy_secret',
  'clean-https': 'https://api.plataforma.dev/v2/orders?page=1&per_page=25&status=paid'
});

export function mountUrlPanel({ rootElement, store, toast }) {
  const formElement = rootElement.querySelector('#url-inspector-form');
  const urlInput = rootElement.querySelector('#url-raw-input');
  const clearUrlBtn = rootElement.querySelector('#url-clear-btn');
  const presetButtons = Array.from(rootElement.querySelectorAll('[data-url-preset]'));

  const statusSlot = rootElement.querySelector('#url-status-slot');
  const anatomySlot = rootElement.querySelector('#url-anatomy-slot');
  const findingsSlot = rootElement.querySelector('#url-findings-slot');

  function runUrlAnalysis(rawUrl) {
    try {
      const inspectionReport = inspectEndpointUrl(rawUrl);
      store.setUrlInspectionResult({ rawUrl, inspectionReport });
    } catch (unexpectedError) {
      console.error('[UrlPanel] Excepción inesperada en el motor estático de URLs:', unexpectedError);
      toast.show('Error inesperado al evaluar la URL.', 'error');
    }
  }

  function renderStatusBanner(report) {
    if (!report || report.isEmpty) {
      statusSlot.innerHTML = `
        <div class="flex flex-wrap items-center justify-between gap-2 rounded-xl bg-slate-950/70 border border-slate-800/90 px-4 py-3 text-xs text-slate-400">
          <span>Introduce una URL o endpoint para ejecutar inspección estática con <code class="font-mono text-slate-300">new URL()</code>.</span>
          <span class="inline-flex items-center gap-1.5 font-mono text-[11px] text-cyan-400">
            <span class="h-1.5 w-1.5 rounded-full bg-cyan-400"></span>Sin peticiones HTTP/DNS externas
          </span>
        </div>
      `;
      return;
    }

    if (!report.isValid) {
      const quickFixMarkup = report.suggestedHttpsUrl
        ? `
          <div class="mt-3 flex flex-wrap items-center gap-2">
            <button
              type="button"
              data-apply-suggestion="${escapeHtml(report.suggestedHttpsUrl)}"
              class="min-h-[44px] rounded-lg bg-cyan-500/15 hover:bg-cyan-500/25 border border-cyan-400/35 px-3.5 py-2 font-mono text-xs font-medium text-cyan-300 transition-colors"
            >
              Autocompletar https://
            </button>
            <button
              type="button"
              data-apply-suggestion="${escapeHtml(report.suggestedHttpUrl)}"
              class="min-h-[44px] rounded-lg bg-slate-800/90 hover:bg-slate-800 border border-slate-700/70 px-3.5 py-2 font-mono text-xs text-slate-300 transition-colors"
            >
              Autocompletar http://
            </button>
          </div>
        `
        : '';

      statusSlot.innerHTML = `
        <div role="alert" class="rounded-xl border border-rose-500/35 bg-rose-500/10 p-4">
          <div class="flex items-center gap-2">
            <span class="inline-flex items-center rounded-md bg-rose-500/20 border border-rose-500/40 px-2 py-0.5 font-mono text-[11px] font-bold text-rose-300">
              FORMATO INVÁLIDO
            </span>
            <h3 class="text-sm font-semibold text-rose-200">No se pudo parsear la URI</h3>
          </div>
          <p class="mt-1.5 text-xs leading-relaxed text-rose-200/85">
            ${escapeHtml(report.errorMessage)}
          </p>
          ${quickFixMarkup}
        </div>
      `;
      return;
    }

    const { highCount, mediumCount, totalFindings } = report.stats;
    const overallBadge =
      totalFindings === 0
        ? `<span class="inline-flex items-center gap-1.5 rounded-full bg-emerald-500/15 border border-emerald-500/30 px-3 py-1 text-xs font-semibold text-emerald-300">
             <span class="h-2 w-2 rounded-full bg-emerald-400"></span>ENDPOINT SEGURO
           </span>`
        : highCount > 0
          ? `<span class="inline-flex items-center gap-1.5 rounded-full bg-rose-500/15 border border-rose-500/35 px-3 py-1 text-xs font-semibold text-rose-300">
               <span class="h-2 w-2 rounded-full bg-rose-500"></span>EXPOSICIÓN CRÍTICA (${highCount})
             </span>`
          : `<span class="inline-flex items-center gap-1.5 rounded-full bg-amber-500/15 border border-amber-500/35 px-3 py-1 text-xs font-semibold text-amber-300">
               <span class="h-2 w-2 rounded-full bg-amber-400"></span>ADVERTENCIA DE CONFIGURACIÓN (${mediumCount})
             </span>`;

    statusSlot.innerHTML = `
      <div class="flex flex-wrap items-center justify-between gap-3 rounded-xl bg-slate-900/90 border border-slate-800 px-4 py-3 shadow-lg shadow-black/20">
        <div class="flex flex-wrap items-center gap-2.5">
          ${overallBadge}
          <span class="text-xs text-slate-400">
            Inspección estática completada en cliente
          </span>
        </div>
        <div class="flex items-center gap-2 font-mono text-xs">
          <span class="rounded-md bg-rose-500/15 border border-rose-500/30 px-2.5 py-1 text-rose-300">ALTA: ${highCount}</span>
          <span class="rounded-md bg-amber-500/15 border border-amber-500/30 px-2.5 py-1 text-amber-300">MEDIA: ${mediumCount}</span>
        </div>
      </div>
    `;
  }

  function renderAnatomyCard(report) {
    if (!report || !report.isValid || !report.anatomy) {
      anatomySlot.innerHTML = '';
      return;
    }

    const { anatomy, sanitizedHref, stats } = report;
    const isSecureScheme = anatomy.protocol === 'HTTPS' || anatomy.protocol === 'WSS';
    const schemeBadgeClass = isSecureScheme
      ? 'text-emerald-300 bg-emerald-500/15 border-emerald-500/30'
      : 'text-rose-300 bg-rose-500/15 border-rose-500/35';

    const queryPillsMarkup =
      anatomy.queryEntries.length === 0
        ? '<span class="text-xs text-slate-500">Sin parámetros en Query String</span>'
        : anatomy.queryEntries
            .map((param) => {
              const badgeStyle = param.isSensitive
                ? 'bg-rose-500/15 border-rose-500/35 text-rose-200'
                : 'bg-slate-950/90 border-slate-800 text-slate-300';
              return `
                <span class="inline-flex items-center gap-1.5 rounded-lg border px-2.5 py-1 font-mono text-xs ${badgeStyle}">
                  <strong class="${param.isSensitive ? 'text-rose-300' : 'text-cyan-300'}">${escapeHtml(param.key)}</strong>
                  <span class="text-slate-500">=</span>
                  <span>${escapeHtml(param.displayValue)}</span>
                </span>
              `;
            })
            .join('');

    const sanitizedSection =
      stats.totalFindings > 0
        ? `
          <div class="mt-4 rounded-xl bg-slate-950/80 border border-slate-800 p-3">
            <div class="flex flex-wrap items-center justify-between gap-2">
              <span class="text-[11px] font-semibold uppercase tracking-wider text-slate-400">
                Vista previa sanitizada para logs / reportes
              </span>
              <button
                type="button"
                data-copy-sanitized="${escapeHtml(sanitizedHref)}"
                class="min-h-[38px] rounded-lg bg-slate-800 hover:bg-slate-700/80 border border-slate-700/70 px-3 py-1.5 text-xs font-medium text-cyan-300 transition-colors"
              >
                Copiar URL redactada
              </button>
            </div>
            <p class="mt-1.5 break-all font-mono text-xs text-slate-300">${escapeHtml(sanitizedHref)}</p>
          </div>
        `
        : '';

    anatomySlot.innerHTML = `
      <section aria-label="Desglose estructural de la URL" class="rounded-2xl bg-slate-900/90 border border-slate-800 p-4 sm:p-5 shadow-lg shadow-black/20">
        <h3 class="text-xs font-semibold uppercase tracking-wider text-slate-400">
          Desglose Estructural (WHATWG URL Parser)
        </h3>

        <div class="mt-3 grid grid-cols-2 sm:grid-cols-4 gap-2.5">
          <div class="rounded-xl bg-slate-950/75 border border-slate-800/90 p-3">
            <span class="block text-[11px] text-slate-500">Protocolo</span>
            <span class="mt-1 inline-block rounded-md border px-2 py-0.5 font-mono text-xs font-semibold ${schemeBadgeClass}">
              ${escapeHtml(anatomy.protocol)}
            </span>
          </div>

          <div class="rounded-xl bg-slate-950/75 border border-slate-800/90 p-3">
            <span class="block text-[11px] text-slate-500">Host</span>
            <span class="mt-1 block truncate font-mono text-xs text-slate-200" title="${escapeHtml(anatomy.hostname)}">
              ${escapeHtml(anatomy.hostname)}
            </span>
          </div>

          <div class="rounded-xl bg-slate-950/75 border border-slate-800/90 p-3">
            <span class="block text-[11px] text-slate-500">Puerto Efectivo</span>
            <span class="mt-1 block font-mono text-xs ${anatomy.explicitPort ? 'text-amber-300' : 'text-slate-200'}">
              :${escapeHtml(anatomy.effectivePort)}${anatomy.explicitPort ? ' (explícito)' : ' (estándar)'}
            </span>
          </div>

          <div class="rounded-xl bg-slate-950/75 border border-slate-800/90 p-3">
            <span class="block text-[11px] text-slate-500">Ruta (Pathname)</span>
            <span class="mt-1 block truncate font-mono text-xs text-slate-300" title="${escapeHtml(anatomy.pathname)}">
              ${escapeHtml(anatomy.pathname)}
            </span>
          </div>
        </div>

        <div class="mt-3.5">
          <span class="block text-[11px] font-medium text-slate-400 mb-2">
            Parámetros de Consulta (${anatomy.queryCount})
          </span>
          <div class="flex flex-wrap gap-2">
            ${queryPillsMarkup}
          </div>
        </div>

        ${sanitizedSection}
      </section>
    `;
  }

  function renderDiagnosticCards(report) {
    if (!report || report.isEmpty || !report.isValid) {
      findingsSlot.innerHTML = `
        <div class="rounded-2xl border border-dashed border-slate-800 bg-slate-900/40 p-7 text-center">
          <p class="text-sm font-medium text-slate-300">Diagnóstico estático listo</p>
          <p class="mt-1 text-xs text-slate-500">
            Se evaluarán protocolo TLS, credenciales <code class="font-mono text-slate-400">user:pass@host</code>, secretos en Query String y exposición de puertos no estándar.
          </p>
        </div>
      `;
      return;
    }

    if (report.findings.length === 0) {
      findingsSlot.innerHTML = `
        <article class="rounded-2xl border border-emerald-500/30 bg-slate-900/90 p-5 shadow-lg shadow-black/20">
          <div class="flex items-center gap-2.5">
            <span class="inline-flex items-center rounded-md bg-emerald-500/15 border border-emerald-500/35 px-2.5 py-0.5 font-mono text-[11px] font-bold text-emerald-300">
              OK · ENDPOINT ENDURECIDO
            </span>
            <span class="text-xs text-slate-400">Sin hallazgos estáticos de riesgo</span>
          </div>
          <h4 class="mt-2.5 text-base font-semibold text-slate-100">
            La estructura de la URL cumple las prácticas recomendadas de transporte
          </h4>
          <p class="mt-1.5 text-xs leading-relaxed text-slate-400">
            Emplea transporte cifrado (<code class="font-mono text-emerald-300">HTTPS/WSS</code>), opera sobre puerto estándar sin exponer motores de datos, carece de credenciales incrustadas en la autoridad y no filtra secretos aparentes en la Query String.
          </p>
        </article>
      `;
      return;
    }

    findingsSlot.innerHTML = report.findings
      .map((finding) => {
        const isHigh = finding.severity === SEVERITY.HIGH;
        const cardBorder = isHigh ? 'border-rose-500/35' : 'border-amber-500/35';
        const badgeStyle = isHigh
          ? 'bg-rose-500/15 text-rose-300 border-rose-500/40'
          : 'bg-amber-500/15 text-amber-300 border-amber-500/40';

        return `
          <article class="rounded-2xl bg-slate-900/90 border ${cardBorder} p-5 shadow-lg shadow-black/20">
            <div class="flex flex-wrap items-center justify-between gap-2">
              <div class="flex flex-wrap items-center gap-2">
                <span class="inline-flex items-center rounded-md border px-2.5 py-0.5 font-mono text-[11px] font-bold tracking-wide ${badgeStyle}">
                  SEVERIDAD ${escapeHtml(finding.severity)}
                </span>
                <span class="rounded-md bg-slate-800 border border-slate-700/60 px-2.5 py-0.5 text-xs font-medium text-slate-300">
                  ${escapeHtml(finding.category)}
                </span>
              </div>
              <code class="rounded-lg bg-slate-950/90 border border-slate-800 px-2.5 py-1 font-mono text-xs text-slate-300">
                ${escapeHtml(finding.evidence)}
              </code>
            </div>

            <h4 class="mt-3 text-base font-semibold text-slate-100">
              ${escapeHtml(finding.title)}
            </h4>

            <p class="mt-2 text-xs sm:text-sm leading-relaxed text-slate-300/90">
              ${escapeHtml(finding.description)}
            </p>

            <div class="mt-3.5 rounded-xl bg-slate-950/85 border border-slate-800/90 p-3.5">
              <span class="block text-[11px] font-semibold uppercase tracking-wider text-cyan-400">
                Recomendación técnica de mitigación
              </span>
              <p class="mt-1 text-xs leading-relaxed text-slate-300">
                ${escapeHtml(finding.mitigation)}
              </p>
            </div>
          </article>
        `;
      })
      .join('');
  }

  function renderFromState(urlSession) {
    const { rawUrl, inspectionReport } = urlSession;
    if (urlInput.value !== rawUrl) {
      urlInput.value = rawUrl;
    }

    renderStatusBanner(inspectionReport);
    renderAnatomyCard(inspectionReport);
    renderDiagnosticCards(inspectionReport);
  }

  formElement.addEventListener('submit', (event) => {
    event.preventDefault();
    runUrlAnalysis(urlInput.value);
  });

  urlInput.addEventListener('input', (event) => {
    runUrlAnalysis(event.target.value);
  });

  clearUrlBtn.addEventListener('click', () => {
    store.clearUrlSession();
    urlInput.focus();
    toast.show('Campo de endpoint limpiado.', 'info');
  });

  presetButtons.forEach((btn) => {
    btn.addEventListener('click', () => {
      const presetKey = btn.dataset.urlPreset;
      const sampleUrl = PRESET_ENDPOINTS[presetKey];
      if (!sampleUrl) {
        return;
      }
      urlInput.value = sampleUrl;
      runUrlAnalysis(sampleUrl);
      toast.show('Escenario de prueba cargado.', 'info');
    });
  });

  statusSlot.addEventListener('click', (event) => {
    const fixButton = event.target.closest('[data-apply-suggestion]');
    if (!fixButton) {
      return;
    }
    const suggestedUrl = fixButton.dataset.applySuggestion;
    urlInput.value = suggestedUrl;
    runUrlAnalysis(suggestedUrl);
  });

  anatomySlot.addEventListener('click', async (event) => {
    const copyBtn = event.target.closest('[data-copy-sanitized]');
    if (!copyBtn) {
      return;
    }
    const redactedUrl = copyBtn.dataset.copySanitized;
    const copied = await copyTextToClipboard(redactedUrl);
    if (copied) {
      toast.show('URL redactada copiada al portapapeles.', 'success');
    }
  });

  store.subscribe((nextState, prevState) => {
    if (nextState.urlSession !== prevState.urlSession) {
      renderFromState(nextState.urlSession);
    }
  });

  renderFromState(store.getState().urlSession);
}
