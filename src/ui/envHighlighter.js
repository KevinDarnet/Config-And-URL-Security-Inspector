/**
 * Resaltador sintáctico ligero para archivos .env sincronizado con <textarea>.
 * Importante: solo aplica propiedades `color` y `background-color` sin alterar padding,
 * border ni font-weight para garantizar alineación exacta de subpíxel con el cursor nativo.
 */

import { SEVERITY } from '../security/envAuditor.js';
import { escapeHtml } from './domUtils.js';

export function renderHighlightedEnvHtml(rawContent, flaggedLineSeverity = new Map()) {
  if (!rawContent) {
    return '';
  }

  const normalized = rawContent.replace(/\r\n?/g, '\n');
  const lines = normalized.split('\n');

  const highlightedLines = lines.map((line, index) => {
    const lineNumber = index + 1;
    const trimmed = line.trim();

    if (trimmed.length === 0) {
      return '';
    }

    if (trimmed.startsWith('#')) {
      return `<span class="text-slate-500">${escapeHtml(line)}</span>`;
    }

    const assignmentMatch = line.match(/^(\s*)(export\s+)?([A-Za-z_][A-Za-z0-9_.-]*)(\s*=\s*)(.*)$/);
    if (!assignmentMatch) {
      return `<span class="text-amber-300 bg-amber-500/10">${escapeHtml(line)}</span>`;
    }

    const [, leadingSpaces, exportKeyword = '', key, delimiter, rest] = assignmentMatch;
    const lineSeverity = flaggedLineSeverity.get(lineNumber);

    const keyClass =
      lineSeverity === SEVERITY.HIGH
        ? 'text-rose-300'
        : lineSeverity === SEVERITY.MEDIUM
          ? 'text-amber-300'
          : 'text-cyan-300';

    const valueClass =
      lineSeverity === SEVERITY.HIGH
        ? 'text-rose-200 bg-rose-500/20'
        : lineSeverity === SEVERITY.MEDIUM
          ? 'text-amber-200 bg-amber-500/15'
          : 'text-slate-300';

    const { valueSegment, commentSegment } = splitInlineCommentForDisplay(rest);

    return [
      escapeHtml(leadingSpaces),
      exportKeyword ? `<span class="text-indigo-400">${escapeHtml(exportKeyword)}</span>` : '',
      `<span class="${keyClass}">${escapeHtml(key)}</span>`,
      `<span class="text-slate-500">${escapeHtml(delimiter)}</span>`,
      valueSegment ? `<span class="${valueClass}">${escapeHtml(valueSegment)}</span>` : '',
      commentSegment ? `<span class="text-slate-500">${escapeHtml(commentSegment)}</span>` : ''
    ].join('');
  });

  // Espacio final cuando el texto termina en salto de línea evita desajuste de scroll en <pre>.
  const joined = highlightedLines.join('\n');
  return normalized.endsWith('\n') ? `${joined} ` : joined;
}

function splitInlineCommentForDisplay(rawRest) {
  const trimmed = rawRest.trimStart();
  if (trimmed.startsWith('"') || trimmed.startsWith("'")) {
    const quote = trimmed[0];
    const quoteOffset = rawRest.indexOf(quote);
    for (let i = quoteOffset + 1; i < rawRest.length; i += 1) {
      if (rawRest[i] === quote && rawRest[i - 1] !== '\\') {
        const afterQuote = rawRest.slice(i + 1);
        const hashIdx = afterQuote.search(/\s*#/);
        if (hashIdx !== -1) {
          const splitPoint = i + 1 + hashIdx;
          return {
            valueSegment: rawRest.slice(0, splitPoint),
            commentSegment: rawRest.slice(splitPoint)
          };
        }
        return { valueSegment: rawRest, commentSegment: '' };
      }
    }
  }

  const inlineHashIndex = rawRest.search(/\s+#/);
  if (inlineHashIndex !== -1) {
    return {
      valueSegment: rawRest.slice(0, inlineHashIndex),
      commentSegment: rawRest.slice(inlineHashIndex)
    };
  }

  return { valueSegment: rawRest, commentSegment: '' };
}
