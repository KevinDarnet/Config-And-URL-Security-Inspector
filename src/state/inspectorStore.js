/**
 * contenedor de estado inmutable en memoria volátil.
 * Por diseño de seguridad, jamás serializamos variables .env ni URLs auditadas
 * en localStorage/sessionStorage para evitar persistencia involuntaria en disco.
 */

const VALID_MODULES = new Set(['env', 'url']);
const VALID_SEVERITY_FILTERS = new Set(['ALL', 'ALTA', 'MEDIA', 'BAJA']);

export function createInitialInspectorState() {
  return Object.freeze({
    activeModule: 'env',
    envSession: Object.freeze({
      rawText: '',
      sourceFileName: null,
      severityFilter: 'ALL',
      sha256Fingerprint: null,
      auditReport: null,
      sanitizedExample: ''
    }),
    urlSession: Object.freeze({
      rawUrl: '',
      inspectionReport: null
    })
  });
}

export function createInspectorStore(initialOverrides = {}) {
  let currentState = Object.freeze({
    ...createInitialInspectorState(),
    ...initialOverrides
  });

  const subscribers = new Set();

  function getState() {
    return currentState;
  }

  function commitNextState(nextPartial, reason) {
    const previousState = currentState;
    currentState = Object.freeze({
      ...previousState,
      ...nextPartial
    });

    for (const notify of subscribers) {
      try {
        notify(currentState, previousState, reason);
      } catch (listenerError) {
        console.error(`[InspectorStore] Fallo en suscriptor durante "${reason}":`, listenerError);
      }
    }
  }

  return Object.freeze({
    getState,

    subscribe(listener) {
      if (typeof listener !== 'function') {
        throw new TypeError('El suscriptor del store debe ser una función.');
      }
      subscribers.add(listener);
      return () => subscribers.delete(listener);
    },

    setActiveModule(moduleId) {
      if (!VALID_MODULES.has(moduleId) || currentState.activeModule === moduleId) {
        return;
      }
      commitNextState({ activeModule: moduleId }, 'module:switch');
    },

    setEnvDraft({ rawText, sourceFileName = null }) {
      commitNextState(
        {
          envSession: Object.freeze({
            ...currentState.envSession,
            rawText,
            sourceFileName,
            auditReport: null,
            sanitizedExample: '',
            sha256Fingerprint: null
          })
        },
        'env:draft'
      );
    },

    setEnvInspectionResult({ rawText, sourceFileName = null, auditReport, sanitizedExample, sha256Fingerprint = null }) {
      commitNextState(
        {
          envSession: Object.freeze({
            ...currentState.envSession,
            rawText,
            sourceFileName,
            auditReport,
            sanitizedExample,
            sha256Fingerprint
          })
        },
        'env:inspected'
      );
    },

    setEnvFingerprint(sha256Fingerprint) {
      if (currentState.envSession.sha256Fingerprint === sha256Fingerprint) {
        return;
      }
      commitNextState(
        {
          envSession: Object.freeze({
            ...currentState.envSession,
            sha256Fingerprint
          })
        },
        'env:fingerprint'
      );
    },

    setEnvSeverityFilter(filterValue) {
      if (!VALID_SEVERITY_FILTERS.has(filterValue) || currentState.envSession.severityFilter === filterValue) {
        return;
      }
      commitNextState(
        {
          envSession: Object.freeze({
            ...currentState.envSession,
            severityFilter: filterValue
          })
        },
        'env:filter'
      );
    },

    clearEnvSession() {
      commitNextState(
        {
          envSession: createInitialInspectorState().envSession
        },
        'env:cleared'
      );
    },

    setUrlDraft(rawUrl) {
      commitNextState(
        {
          urlSession: Object.freeze({
            rawUrl,
            inspectionReport: null
          })
        },
        'url:draft'
      );
    },

    setUrlInspectionResult({ rawUrl, inspectionReport }) {
      commitNextState(
        {
          urlSession: Object.freeze({
            rawUrl,
            inspectionReport
          })
        },
        'url:inspected'
      );
    },

    clearUrlSession() {
      commitNextState(
        {
          urlSession: createInitialInspectorState().urlSession
        },
        'url:cleared'
      );
    }
  });
}
