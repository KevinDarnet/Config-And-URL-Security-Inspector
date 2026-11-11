/**
 * Utilidades seguras de interfaz y portapapeles usando APIs estándar del navegador.
 */

import { generateSecurityAuditPdf } from '../security/pdfReportGenerator.js';

const HTML_ESCAPE_MAP = Object.freeze({
  '&': '&amp;',
  '<': '&lt;',
  '>': '&gt;',
  '"': '&quot;',
  "'": '&#39;'
});

/**
 * Escapa cualquier entrada antes de interpolarla en plantillas HTML para impedir
 * auto-XSS al inspeccionar URLs o variables .env con payloads maliciosos.
 */
export function escapeHtml(unsafeValue) {
  return String(unsafeValue ?? '').replace(/[&<>"']/g, (char) => HTML_ESCAPE_MAP[char]);
}

/**
 * Copia texto al portapapeles con fallback defensivo cuando la API asíncrona
 * está restringida fuera de contextos HTTPS/localhost (ej. pruebas móviles por IP LAN).
 */
export async function copyTextToClipboard(text) {
  if (typeof text !== 'string' || text.length === 0) {
    return false;
  }

  if (globalThis.navigator?.clipboard?.writeText) {
    try {
      await globalThis.navigator.clipboard.writeText(text);
      return true;
    } catch (clipboardError) {
      console.warn('[Clipboard] navigator.clipboard falló, aplicando fallback con selección temporal:', clipboardError);
    }
  }

  try {
    const scratchInput = document.createElement('textarea');
    scratchInput.value = text;
    scratchInput.setAttribute('readonly', '');
    scratchInput.style.position = 'fixed';
    scratchInput.style.opacity = '0';
    scratchInput.style.pointerEvents = 'none';
    document.body.appendChild(scratchInput);
    scratchInput.select();
    const succeeded = document.execCommand('copy');
    document.body.removeChild(scratchInput);
    return succeeded;
  } catch (fallbackError) {
    console.error('[Clipboard] No fue posible copiar al portapapeles:', fallbackError);
    return false;
  }
}

export function triggerBlobDownload(fileName, blob) {
  try {
    const objectUrl = URL.createObjectURL(blob);
    const downloadLink = document.createElement('a');
    downloadLink.href = objectUrl;
    downloadLink.download = fileName;
    document.body.appendChild(downloadLink);
    downloadLink.click();
    document.body.removeChild(downloadLink);
    setTimeout(() => URL.revokeObjectURL(objectUrl), 1500);
    return true;
  } catch (downloadError) {
    console.error('[FileDownload] Error al generar descarga local:', downloadError);
    return false;
  }
}

export function downloadPlainTextFile(fileName, content) {
  const fileBlob = new Blob([content], { type: 'text/plain;charset=utf-8' });
  return triggerBlobDownload(fileName, fileBlob);
}

export function exportSecurityReportPdf({ mode, session, toast }) {
  try {
    const { fileName, blob } = generateSecurityAuditPdf({ mode, session });
    if (triggerBlobDownload(fileName, blob)) {
      toast?.show(`Reporte PDF "${fileName}" generado localmente.`, 'success');
      return true;
    }
    toast?.show('No se pudo iniciar la descarga del reporte PDF.', 'error');
    return false;
  } catch (pdfError) {
    console.error(`[PdfExport] Error al generar reporte PDF (${mode}):`, pdfError);
    toast?.show('Error al generar el reporte PDF en el navegador.', 'error');
    return false;
  }
}
