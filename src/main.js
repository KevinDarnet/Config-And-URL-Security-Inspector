/**
 * Punto de entrada de Config & URL Security Inspector.
 * Coordina navegación accesible por pestañas tipo pill y montaje de controladores.
 */

import { createInspectorStore } from './state/inspectorStore.js';
import { createToastNotifier } from './ui/toastNotifier.js';
import { mountEnvPanel } from './ui/envPanelController.js';
import { mountUrlPanel } from './ui/urlPanelController.js';

function initSecurityInspectorApp() {
  const store = createInspectorStore();
  const toastContainer = document.querySelector('#inspector-toast');
  const toast = createToastNotifier(toastContainer);

  const tabButtons = Array.from(document.querySelectorAll('[role="tab"][data-module-tab]'));
  const tabPanels = new Map([
    ['env', document.querySelector('#panel-env')],
    ['url', document.querySelector('#panel-url')]
  ]);

  const envTabCounter = document.querySelector('#tab-badge-env');
  const urlTabCounter = document.querySelector('#tab-badge-url');

  function syncActiveTabView(activeModule) {
    for (const tabBtn of tabButtons) {
      const moduleId = tabBtn.dataset.moduleTab;
      const isSelected = moduleId === activeModule;

      tabBtn.setAttribute('aria-selected', String(isSelected));
      tabBtn.tabIndex = isSelected ? 0 : -1;

      if (isSelected) {
        tabBtn.className =
          'group relative flex flex-1 sm:flex-initial min-h-[46px] items-center justify-center gap-2.5 rounded-xl bg-slate-800 border border-cyan-500/40 px-4 sm:px-5 py-2.5 text-xs sm:text-sm font-semibold text-cyan-300 shadow-argon-glow transition-all';
      } else {
        tabBtn.className =
          'group relative flex flex-1 sm:flex-initial min-h-[46px] items-center justify-center gap-2.5 rounded-xl border border-transparent hover:bg-slate-800/45 px-4 sm:px-5 py-2.5 text-xs sm:text-sm font-medium text-slate-400 hover:text-slate-200 transition-all';
      }
    }

    for (const [moduleId, panelEl] of tabPanels.entries()) {
      if (!panelEl) {
        continue;
      }
      panelEl.hidden = moduleId !== activeModule;
    }
  }

  function updateTabMicroBadges(state) {
    const envCount = state.envSession.auditReport?.findings.length ?? 0;
    const urlCount = state.urlSession.inspectionReport?.findings.length ?? 0;

    if (envTabCounter) {
      envTabCounter.textContent = String(envCount);
      envTabCounter.hidden = envCount === 0;
    }

    if (urlTabCounter) {
      urlTabCounter.textContent = String(urlCount);
      urlTabCounter.hidden = urlCount === 0;
    }
  }

  tabButtons.forEach((tabBtn, index) => {
    tabBtn.addEventListener('click', () => {
      store.setActiveModule(tabBtn.dataset.moduleTab);
    });

    // Soporte completo de teclado conforme al patrón WAI-ARIA Tabs.
    tabBtn.addEventListener('keydown', (event) => {
      if (event.key !== 'ArrowRight' && event.key !== 'ArrowLeft') {
        return;
      }
      event.preventDefault();
      const direction = event.key === 'ArrowRight' ? 1 : -1;
      const nextIndex = (index + direction + tabButtons.length) % tabButtons.length;
      const nextTab = tabButtons[nextIndex];
      nextTab.focus();
      store.setActiveModule(nextTab.dataset.moduleTab);
    });
  });

  store.subscribe((nextState, prevState) => {
    if (nextState.activeModule !== prevState.activeModule) {
      syncActiveTabView(nextState.activeModule);
    }
    updateTabMicroBadges(nextState);
  });

  try {
    const envPanelRoot = tabPanels.get('env');
    const urlPanelRoot = tabPanels.get('url');

    if (envPanelRoot) {
      mountEnvPanel({ rootElement: envPanelRoot, store, toast });
    }
    if (urlPanelRoot) {
      mountUrlPanel({ rootElement: urlPanelRoot, store, toast });
    }

    syncActiveTabView(store.getState().activeModule);
    updateTabMicroBadges(store.getState());

    console.info('[SecurityInspector] Inicializado en modo 100% client-side (memoria volátil, cero llamadas de red).');
  } catch (bootstrapError) {
    console.error('[SecurityInspector] Error crítico durante la inicialización:', bootstrapError);
  }
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initSecurityInspectorApp, { once: true });
} else {
  initSecurityInspectorApp();
}
