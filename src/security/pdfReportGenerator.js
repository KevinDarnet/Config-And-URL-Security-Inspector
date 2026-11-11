/**
 * Generador puro de reportes PDF 1.4 en Vanilla JS (100% Client-Side, cero red).
 * Emite un documento binario válido con codificación WinAnsi mediante escapes octales
 * para garantizar coincidencia exacta entre longitud ASCII y offsets de la tabla xref.
 */

import { SEVERITY } from './envAuditor.js';

const PAGE_WIDTH = 595.28; // A4 en puntos PostScript
const PAGE_HEIGHT = 841.89;
const MARGIN_X = 44;
const MARGIN_TOP = 46;
const MARGIN_BOTTOM = 48;
const CONTENT_WIDTH = PAGE_WIDTH - MARGIN_X * 2;

const WIN_ANSI_EXTENDED = new Map([
  [0x20ac, 0x80], // €
  [0x201a, 0x82], // ‚
  [0x0192, 0x83], // ƒ
  [0x201e, 0x84], // „
  [0x2026, 0x85], // …
  [0x2020, 0x86], // †
  [0x2021, 0x87], // ‡
  [0x02c6, 0x88], // ˆ
  [0x2030, 0x89], // ‰
  [0x0160, 0x8a], // Š
  [0x2039, 0x8b], // ‹
  [0x0152, 0x8c], // Œ
  [0x017d, 0x8e], // Ž
  [0x2018, 0x91], // ‘
  [0x2019, 0x92], // ’
  [0x201c, 0x93], // “
  [0x201d, 0x94], // ”
  [0x2022, 0x95], // •
  [0x2013, 0x96], // –
  [0x2014, 0x97], // —
  [0x02dc, 0x98], // ˜
  [0x2122, 0x99], // ™
  [0x0161, 0x9a], // š
  [0x203a, 0x9b], // ›
  [0x0153, 0x9c], // œ
  [0x017e, 0x9e], // ž
  [0x0178, 0x9f]  // Ÿ
]);

export function formatLocalDateStamp(date = new Date()) {
  const year = date.getFullYear();
  const month = String(date.getMonth() + 1).padStart(2, '0');
  const day = String(date.getDate()).padStart(2, '0');
  return `${year}-${month}-${day}`;
}

export function formatLocalDateTime(date = new Date()) {
  const datePart = formatLocalDateStamp(date);
  const hours = String(date.getHours()).padStart(2, '0');
  const minutes = String(date.getMinutes()).padStart(2, '0');
  const seconds = String(date.getSeconds()).padStart(2, '0');
  return `${datePart} ${hours}:${minutes}:${seconds}`;
}

export function buildReportFileName(date = new Date()) {
  return `reporte-seguridad-${formatLocalDateStamp(date)}.pdf`;
}

function normalizeForWinAnsi(text) {
  return String(text ?? '')
    .replace(/\r\n?/g, '\n')
    .replace(/→/g, '->')
    .replace(/←/g, '<-')
    .replace(/·/g, '|')
    .replace(/\t/g, '  ');
}

function encodePdfLiteralString(rawText) {
  const normalized = normalizeForWinAnsi(rawText);
  let output = '(';

  for (const ch of normalized) {
    const code = ch.codePointAt(0);
    if (code === 0x5c || code === 0x28 || code === 0x29) {
      output += `\\${ch}`;
    } else if (code >= 0x20 && code <= 0x7e) {
      output += ch;
    } else if (code >= 0xa0 && code <= 0xff) {
      output += `\\${code.toString(8).padStart(3, '0')}`;
    } else if (WIN_ANSI_EXTENDED.has(code)) {
      output += `\\${WIN_ANSI_EXTENDED.get(code).toString(8).padStart(3, '0')}`;
    } else {
      output += '?';
    }
  }

  return `${output})`;
}

function estimateCharWidth(char, fontKey, fontSize) {
  if (fontKey === 'F3' || fontKey === 'F4') {
    return fontSize * 0.6;
  }
  const factor = fontKey === 'F2' ? 1.05 : 1.0;
  if ('iIl1.,:;|!\'`'.includes(char)) {
    return fontSize * 0.28 * factor;
  }
  if ('mwMW@#%&QOG'.includes(char)) {
    return fontSize * 0.78 * factor;
  }
  if (char === char.toUpperCase() && char !== char.toLowerCase()) {
    return fontSize * 0.64 * factor;
  }
  return fontSize * 0.51 * factor;
}

function measureTextWidth(text, fontKey, fontSize) {
  let width = 0;
  for (const char of text) {
    width += estimateCharWidth(char, fontKey, fontSize);
  }
  return width;
}

function wrapTextLines(rawText, maxWidth, fontKey, fontSize) {
  const normalized = normalizeForWinAnsi(rawText);
  const paragraphs = normalized.split('\n');
  const wrapped = [];

  for (const paragraph of paragraphs) {
    if (paragraph.length === 0) {
      wrapped.push('');
      continue;
    }

    const words = paragraph.split(/(\s+)/);
    let currentLine = '';

    for (const token of words) {
      if (!token) {
        continue;
      }

      const candidate = currentLine + token;
      if (measureTextWidth(candidate, fontKey, fontSize) <= maxWidth) {
        currentLine = candidate;
        continue;
      }

      if (currentLine.trim().length > 0) {
        wrapped.push(currentLine.trimEnd());
        currentLine = '';
      }

      // Token más ancho que la línea (ej. URL larga o clave sin espacios): corte por carácter.
      if (measureTextWidth(token, fontKey, fontSize) > maxWidth) {
        let chunk = '';
        for (const char of token.trimStart()) {
          if (measureTextWidth(chunk + char, fontKey, fontSize) > maxWidth && chunk.length > 0) {
            wrapped.push(chunk);
            chunk = char;
          } else {
            chunk += char;
          }
        }
        currentLine = chunk;
      } else {
        currentLine = token.trimStart();
      }
    }

    if (currentLine.length > 0) {
      wrapped.push(currentLine.trimEnd());
    }
  }

  return wrapped.length > 0 ? wrapped : [''];
}

function createPdfCanvas() {
  const pages = [[]];
  let cursorY = PAGE_HEIGHT - MARGIN_TOP;

  function activeCommands() {
    return pages[pages.length - 1];
  }

  function addPage() {
    pages.push([]);
    cursorY = PAGE_HEIGHT - MARGIN_TOP;
  }

  function ensureSpace(requiredHeight) {
    if (cursorY - requiredHeight < MARGIN_BOTTOM + 20) {
      addPage();
      return true;
    }
    return false;
  }

  function drawRect(x, yBottom, width, height, fillRgb, strokeRgb = null, lineWidth = 0.75) {
    const cmds = activeCommands();
    cmds.push('q');
    if (fillRgb) {
      cmds.push(`${fillRgb[0]} ${fillRgb[1]} ${fillRgb[2]} rg`);
    }
    if (strokeRgb) {
      cmds.push(`${lineWidth} w ${strokeRgb[0]} ${strokeRgb[1]} ${strokeRgb[2]} RG`);
    }
    const op = fillRgb && strokeRgb ? 'B' : fillRgb ? 'f' : 'S';
    cmds.push(`${x.toFixed(2)} ${yBottom.toFixed(2)} ${width.toFixed(2)} ${height.toFixed(2)} re ${op}`);
    cmds.push('Q');
  }

  function drawLine(x1, y1, x2, y2, strokeRgb, lineWidth = 0.75) {
    activeCommands().push(
      `q ${lineWidth} w ${strokeRgb[0]} ${strokeRgb[1]} ${strokeRgb[2]} RG ${x1.toFixed(2)} ${y1.toFixed(2)} m ${x2.toFixed(2)} ${y2.toFixed(2)} l S Q`
    );
  }

  function drawText(text, x, yBaseline, fontKey, fontSize, rgb) {
    activeCommands().push(
      `BT /${fontKey} ${fontSize.toFixed(2)} Tf ${rgb[0]} ${rgb[1]} ${rgb[2]} rg 1 0 0 1 ${x.toFixed(2)} ${yBaseline.toFixed(2)} Tm ${encodePdfLiteralString(text)} Tj ET`
    );
  }

  return {
    getCursorY: () => cursorY,
    moveCursor: (delta) => {
      cursorY -= delta;
    },
    ensureSpace,
    drawRect,
    drawLine,
    drawText,
    finalizePages: (footerLeftText) => {
      const total = pages.length;
      return pages.map((cmds, index) => {
        const pageNum = index + 1;
        const footerY = MARGIN_BOTTOM - 18;
        const lineCmd = `q 0.5 w 0.80 0.84 0.88 RG ${MARGIN_X.toFixed(2)} ${(footerY + 12).toFixed(2)} m ${(PAGE_WIDTH - MARGIN_X).toFixed(2)} ${(footerY + 12).toFixed(2)} l S Q`;
        const leftCmd = `BT /F1 8 Tf 0.39 0.45 0.55 rg 1 0 0 1 ${MARGIN_X.toFixed(2)} ${footerY.toFixed(2)} Tm ${encodePdfLiteralString(footerLeftText)} Tj ET`;
        const pageLabel = `Página ${pageNum} de ${total}`;
        const rightX = PAGE_WIDTH - MARGIN_X - measureTextWidth(pageLabel, 'F1', 8);
        const rightCmd = `BT /F1 8 Tf 0.39 0.45 0.55 rg 1 0 0 1 ${rightX.toFixed(2)} ${footerY.toFixed(2)} Tm ${encodePdfLiteralString(pageLabel)} Tj ET`;
        return [...cmds, lineCmd, leftCmd, rightCmd].join('\n');
      });
    }
  };
}

function serializePdfDocument(pageStreams) {
  const objects = [];
  const addObject = (body) => {
    objects.push(body);
    return objects.length;
  };

  // Objetos 1..4: Fuentes estándar Type1 WinAnsi
  const fontRegularId = addObject('<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>');
  const fontBoldId = addObject('<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>');
  const fontMonoId = addObject('<< /Type /Font /Subtype /Type1 /BaseFont /Courier /Encoding /WinAnsiEncoding >>');
  const fontMonoBoldId = addObject('<< /Type /Font /Subtype /Type1 /BaseFont /Courier-Bold /Encoding /WinAnsiEncoding >>');

  const pagesObjectId = 5;
  objects.push(''); // Placeholder reservado para /Pages

  const pageIds = [];
  for (const streamBody of pageStreams) {
    const contentId = addObject(`<< /Length ${streamBody.length} >>\nstream\n${streamBody}\nendstream`);
    const pageId = addObject(
      `<< /Type /Page /Parent ${pagesObjectId} 0 R /MediaBox [0 0 ${PAGE_WIDTH} ${PAGE_HEIGHT}] ` +
      `/Resources << /Font << /F1 ${fontRegularId} 0 R /F2 ${fontBoldId} 0 R /F3 ${fontMonoId} 0 R /F4 ${fontMonoBoldId} 0 R >> >> ` +
      `/Contents ${contentId} 0 R >>`
    );
    pageIds.push(pageId);
  }

  objects[pagesObjectId - 1] = `<< /Type /Pages /Kids [${pageIds.map((id) => `${id} 0 R`).join(' ')}] /Count ${pageIds.length} >>`;
  const catalogId = addObject(`<< /Type /Catalog /Pages ${pagesObjectId} 0 R >>`);

  let pdfText = '%PDF-1.4\n';
  const offsets = [0];

  for (let i = 0; i < objects.length; i += 1) {
    offsets.push(pdfText.length);
    pdfText += `${i + 1} 0 obj\n${objects[i]}\nendobj\n`;
  }

  const xrefOffset = pdfText.length;
  pdfText += `xref\n0 ${objects.length + 1}\n`;
  pdfText += '0000000000 65535 f \n';
  for (let i = 1; i < offsets.length; i += 1) {
    pdfText += `${String(offsets[i]).padStart(10, '0')} 00000 n \n`;
  }

  pdfText += `trailer\n<< /Size ${objects.length + 1} /Root ${catalogId} 0 R >>\nstartxref\n${xrefOffset}\n%%EOF\n`;

  const bytes = new Uint8Array(pdfText.length);
  for (let i = 0; i < pdfText.length; i += 1) {
    bytes[i] = pdfText.charCodeAt(i) & 0xff;
  }
  return bytes;
}

const COLORS = Object.freeze({
  headerBg: [0.059, 0.090, 0.165],
  cyan: [0.024, 0.714, 0.831],
  white: [0.973, 0.980, 0.988],
  slateLight: [0.580, 0.639, 0.722],
  slateDark: [0.118, 0.161, 0.231],
  slateMuted: [0.278, 0.333, 0.412],
  boxBg: [0.973, 0.980, 0.988],
  boxBorder: [0.800, 0.835, 0.882],
  highBg: [0.996, 0.949, 0.949],
  highText: [0.745, 0.071, 0.235],
  medBg: [1.000, 0.984, 0.922],
  medText: [0.706, 0.325, 0.035],
  lowBg: [0.941, 0.976, 1.000],
  lowText: [0.012, 0.412, 0.631],
  okBg: [0.925, 0.992, 0.961],
  okText: [0.024, 0.471, 0.341]
});

function renderSummaryHeader(canvas, reportData) {
  const { moduleLabel, generatedAtLabel, summary } = reportData;
  const headerHeight = 82;
  const headerTop = canvas.getCursorY();

  canvas.drawRect(MARGIN_X, headerTop - headerHeight, CONTENT_WIDTH, headerHeight, COLORS.headerBg);
  canvas.drawRect(MARGIN_X, headerTop - headerHeight, CONTENT_WIDTH, 3, COLORS.cyan);

  canvas.drawText('Reporte de Auditoría de Seguridad', MARGIN_X + 16, headerTop - 24, 'F2', 16, COLORS.white);
  canvas.drawText(
    `Módulo: ${moduleLabel}  |  Generado: ${generatedAtLabel}`,
    MARGIN_X + 16,
    headerTop - 41,
    'F1',
    9.5,
    COLORS.slateLight
  );
  canvas.drawText(
    'Origen: Entrada provista por el usuario (Evaluación en memoria local)',
    MARGIN_X + 16,
    headerTop - 55,
    'F1',
    8.5,
    COLORS.white
  );
  canvas.drawText('100% Client-Side | Datos sensibles redactados', MARGIN_X + 16, headerTop - 70, 'F3', 8, COLORS.cyan);

  canvas.moveCursor(headerHeight + 14);

  // Tira de resumen de severidades (Críticas, Altas, Medias, Bajas)
  const cardGap = 7;
  const cardWidth = (CONTENT_WIDTH - cardGap * 4) / 5;
  const cardHeight = 42;
  const cards = [
    { label: 'CRÍTICAS', value: String(summary.criticalCount), bg: COLORS.highBg, accent: COLORS.highText },
    { label: 'ALTAS', value: String(summary.highCount), bg: COLORS.highBg, accent: COLORS.highText },
    { label: 'MEDIAS', value: String(summary.mediumCount), bg: COLORS.medBg, accent: COLORS.medText },
    { label: 'BAJAS', value: String(summary.lowCount ?? 0), bg: COLORS.lowBg, accent: COLORS.lowText },
    { label: 'TOTAL', value: String(summary.totalFindings), bg: COLORS.boxBg, accent: COLORS.slateDark }
  ];

  const cardBottom = canvas.getCursorY() - cardHeight;
  cards.forEach((card, idx) => {
    const x = MARGIN_X + idx * (cardWidth + cardGap);
    canvas.drawRect(x, cardBottom, cardWidth, cardHeight, card.bg, COLORS.boxBorder, 0.6);
    canvas.drawText(card.label, x + 10, cardBottom + 27, 'F2', 7.5, COLORS.slateMuted);
    canvas.drawText(card.value, x + 10, cardBottom + 10, 'F2', 14, card.accent);
  });

  canvas.moveCursor(cardHeight + 18);
}

function renderRedactedDataSection(canvas, sectionTitle, metadataLines, codeLines) {
  canvas.ensureSpace(70);
  canvas.drawText(sectionTitle, MARGIN_X, canvas.getCursorY() - 10, 'F2', 11.5, COLORS.slateDark);
  canvas.moveCursor(16);

  for (const meta of metadataLines) {
    const wrappedMeta = wrapTextLines(meta, CONTENT_WIDTH, 'F1', 9);
    for (const line of wrappedMeta) {
      canvas.ensureSpace(14);
      canvas.drawText(line, MARGIN_X, canvas.getCursorY() - 9, 'F1', 9, COLORS.slateMuted);
      canvas.moveCursor(13);
    }
  }

  canvas.moveCursor(4);
  const innerWidth = CONTENT_WIDTH - 20;
  const wrappedCode = [];
  for (const rawLine of codeLines) {
    wrappedCode.push(...wrapTextLines(rawLine, innerWidth, 'F3', 8.2));
  }

  // Renderizado paginado del bloque sanitizado para soportar archivos .env extensos
  let cursorIdx = 0;
  while (cursorIdx < wrappedCode.length) {
    const available = canvas.getCursorY() - (MARGIN_BOTTOM + 24);
    const maxLinesFit = Math.max(1, Math.floor((available - 16) / 11.5));
    const slice = wrappedCode.slice(cursorIdx, cursorIdx + maxLinesFit);
    const blockHeight = slice.length * 11.5 + 14;

    if (available < 30) {
      canvas.ensureSpace(blockHeight);
      continue;
    }

    const boxBottom = canvas.getCursorY() - blockHeight;
    canvas.drawRect(MARGIN_X, boxBottom, CONTENT_WIDTH, blockHeight, COLORS.boxBg, COLORS.boxBorder, 0.6);

    let lineY = canvas.getCursorY() - 15;
    for (const codeLine of slice) {
      canvas.drawText(codeLine, MARGIN_X + 10, lineY, 'F3', 8.2, COLORS.slateDark);
      lineY -= 11.5;
    }

    canvas.moveCursor(blockHeight + 10);
    cursorIdx += slice.length;
    if (cursorIdx < wrappedCode.length) {
      canvas.ensureSpace(40);
    }
  }

  canvas.moveCursor(8);
}

function renderFindingsSection(canvas, findings) {
  canvas.ensureSpace(50);
  canvas.drawText(`Detalle de Hallazgos (${findings.length})`, MARGIN_X, canvas.getCursorY() - 10, 'F2', 11.5, COLORS.slateDark);
  canvas.moveCursor(18);

  if (findings.length === 0) {
    const boxHeight = 46;
    canvas.ensureSpace(boxHeight);
    const boxBottom = canvas.getCursorY() - boxHeight;
    canvas.drawRect(MARGIN_X, boxBottom, CONTENT_WIDTH, boxHeight, COLORS.okBg, COLORS.okText, 0.75);
    canvas.drawText('Sin riesgos detectados', MARGIN_X + 12, boxBottom + 27, 'F2', 10.5, COLORS.okText);
    canvas.drawText(
      'La inspección estática no identificó secretos expuestos, credenciales ni configuraciones inseguras.',
      MARGIN_X + 12,
      boxBottom + 12,
      'F1',
      9,
      COLORS.slateDark
    );
    canvas.moveCursor(boxHeight + 12);
    return;
  }

  const innerWidth = CONTENT_WIDTH - 24;

  findings.forEach((finding, index) => {
    const titleLines = wrapTextLines(`${index + 1}. ${finding.title}`, innerWidth, 'F2', 10);
    const impactLines = wrapTextLines(`Impacto: ${finding.impact}`, innerWidth, 'F1', 9);
    const mitigationLines = wrapTextLines(`Mitigación: ${finding.mitigation}`, innerWidth, 'F1', 9);

    const cardHeight =
      18 +
      titleLines.length * 13 +
      6 +
      impactLines.length * 12 +
      6 +
      mitigationLines.length * 12 +
      12;

    canvas.ensureSpace(cardHeight + 8);
    const cardTop = canvas.getCursorY();
    const cardBottom = cardTop - cardHeight;

    const isHigh = finding.severity === SEVERITY.HIGH || finding.severity === 'CRÍTICA';
    const isMedium = finding.severity === SEVERITY.MEDIUM;
    const badgeBg = isHigh ? COLORS.highBg : isMedium ? COLORS.medBg : COLORS.lowBg;
    const badgeColor = isHigh ? COLORS.highText : isMedium ? COLORS.medText : COLORS.lowText;

    canvas.drawRect(MARGIN_X, cardBottom, CONTENT_WIDTH, cardHeight, [1, 1, 1], COLORS.boxBorder, 0.65);
    canvas.drawRect(MARGIN_X, cardBottom, 3.5, cardHeight, badgeColor);

    const pillText = `[${finding.severity}]`;
    const pillWidth = measureTextWidth(pillText, 'F4', 8) + 12;
    canvas.drawRect(MARGIN_X + 12, cardTop - 21, pillWidth, 14, badgeBg);
    canvas.drawText(pillText, MARGIN_X + 18, cardTop - 17, 'F4', 8, badgeColor);

    if (finding.metaTag) {
      canvas.drawText(finding.metaTag, MARGIN_X + 20 + pillWidth, cardTop - 17, 'F3', 8, COLORS.slateMuted);
    }

    let textY = cardTop - 35;
    for (const line of titleLines) {
      canvas.drawText(line, MARGIN_X + 12, textY, 'F2', 10, COLORS.slateDark);
      textY -= 13;
    }

    textY -= 3;
    for (const line of impactLines) {
      canvas.drawText(line, MARGIN_X + 12, textY, 'F1', 9, COLORS.slateMuted);
      textY -= 12;
    }

    textY -= 3;
    canvas.drawLine(MARGIN_X + 12, textY + 7, MARGIN_X + CONTENT_WIDTH - 12, textY + 7, COLORS.boxBorder, 0.45);
    for (const line of mitigationLines) {
      canvas.drawText(line, MARGIN_X + 12, textY - 3, 'F1', 9, COLORS.slateDark);
      textY -= 12;
    }

    canvas.moveCursor(cardHeight + 10);
  });
}

function normalizeEnvReportData(envSession, now) {
  const { auditReport, sourceFileName, sha256Fingerprint, sanitizedExample } = envSession;
  const stats = auditReport?.stats || { analyzedKeys: 0, highCount: 0, mediumCount: 0 };
  const rawFindings = auditReport?.findings || [];

  const sanitizedLines = (sanitizedExample || '')
    .split('\n')
    .filter((line) => line.trim().length > 0)
    .slice(0, 60);

  if (sanitizedLines.length === 0) {
    sanitizedLines.push('# Sin variables analizadas');
  }

  return {
    moduleLabel: 'Auditor de Archivos .env',
    generatedAtLabel: formatLocalDateTime(now),
    summary: {
      criticalCount: 0,
      highCount: stats.highCount,
      mediumCount: stats.mediumCount,
      lowCount: stats.lowCount ?? 0,
      totalFindings: rawFindings.length
    },
    sectionTitle: 'Configuración Analizada (Sanitizada a .env.example)',
    metadataLines: [
      `Archivo / Fuente: ${sourceFileName || 'Entrada directa en editor'}  |  Variables analizadas: ${stats.analyzedKeys}`,
      `Huella SHA-256 local: ${sha256Fingerprint || 'No disponible fuera de contexto seguro'}`
    ],
    codeLines: sanitizedLines,
    findings: rawFindings.map((item) => {
      const lineNum = item.line ?? item.lineNumber;
      const evidence = item.evidenceRedacted ?? item.maskedPreview;
      return {
        severity: item.severity,
        metaTag: `Línea ${lineNum} | ${item.category} | Evidencia: ${evidence}`,
        title: `${item.title} (${item.key})`,
        impact: item.impact || `Variable "${item.key}" en línea ${lineNum} expone un valor de riesgo (${evidence}).`,
        mitigation: item.mitigation ?? item.remediation
      };
    })
  };
}

function redactFragmentForReport(rawUrl) {
  try {
    const parsed = new URL(rawUrl);
    if (parsed.hash && /(?:access_token|id_token|token|secret|key)=/i.test(parsed.hash)) {
      return `${parsed.origin}${parsed.pathname}${parsed.search}#<REDACTED_FRAGMENT>`;
    }
  } catch {
    // Si falla el parseo, el reporte ya utiliza sanitizedHref pre-calculado.
  }
  return null;
}

function normalizeUrlReportData(urlSession, now) {
  const { rawUrl, inspectionReport } = urlSession;
  const stats = inspectionReport?.stats || { highCount: 0, mediumCount: 0, totalFindings: 0 };
  const anatomy = inspectionReport?.anatomy;
  const rawFindings = inspectionReport?.findings || [];

  const redactedUrl =
    redactFragmentForReport(inspectionReport?.sanitizedHref || rawUrl) ||
    inspectionReport?.sanitizedHref ||
    '(URL no disponible)';

  const codeLines = [`Endpoint redactado: ${redactedUrl}`];
  if (anatomy) {
    codeLines.push(
      `Protocolo: ${anatomy.protocol}  |  Host: ${anatomy.hostname}  |  Puerto efectivo: :${anatomy.effectivePort}`
    );
    codeLines.push(`Ruta (Pathname): ${anatomy.pathname}`);
    if (anatomy.queryEntries.length > 0) {
      const paramSummary = anatomy.queryEntries.map((p) => `${p.key}=${p.displayValue}`).join('&');
      codeLines.push(`Query String sanitizada: ?${paramSummary}`);
    } else {
      codeLines.push('Query String: (sin parámetros)');
    }
  }

  return {
    moduleLabel: 'Analizador Estático de URLs / Endpoints',
    generatedAtLabel: formatLocalDateTime(now),
    summary: {
      criticalCount: 0,
      highCount: stats.highCount,
      mediumCount: stats.mediumCount,
      lowCount: 0,
      totalFindings: rawFindings.length
    },
    sectionTitle: 'Endpoint Analizado (Credenciales y Tokens Redactados)',
    metadataLines: [
      `Estado de parseo: WHATWG new URL() válido  |  Parámetros inspeccionados: ${anatomy?.queryCount ?? 0}`
    ],
    codeLines,
    findings: rawFindings.map((item) => ({
      severity: item.severity,
      metaTag: `${item.category} | Evidencia: ${item.evidence}`,
      title: item.title,
      impact: item.description,
      mitigation: item.mitigation
    }))
  };
}

/**
 * Construye los bytes PDF para un reporte de auditoría (.env o URL) sin llamadas externas.
 * @returns {{ fileName: string, pdfBytes: Uint8Array, blob: Blob }}
 */
export function generateSecurityAuditPdf({ mode, session, now = new Date() }) {
  if (mode !== 'env' && mode !== 'url') {
    throw new Error(`Modo de reporte PDF no soportado: ${String(mode)}`);
  }

  const reportData =
    mode === 'env' ? normalizeEnvReportData(session, now) : normalizeUrlReportData(session, now);

  const canvas = createPdfCanvas();
  renderSummaryHeader(canvas, reportData);
  renderRedactedDataSection(canvas, reportData.sectionTitle, reportData.metadataLines, reportData.codeLines);
  renderFindingsSection(canvas, reportData.findings);

  const finalizedPages = canvas.finalizePages(
    'Config & URL Security Inspector - Reporte generado localmente en navegador'
  );
  const pdfBytes = serializePdfDocument(finalizedPages);
  const fileName = buildReportFileName(now);

  return {
    fileName,
    pdfBytes,
    blob: new Blob([pdfBytes], { type: 'application/pdf' })
  };
}
