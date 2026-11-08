/**
 * Notificador accesible y no bloqueante estilo Argon Dark (aria-live="polite").
 */

const VARIANT_STYLES = Object.freeze({
  success: {
    border: 'border-emerald-500/35',
    badgeBg: 'bg-emerald-500/15 text-emerald-300',
    dot: 'bg-emerald-400'
  },
  warning: {
    border: 'border-amber-500/35',
    badgeBg: 'bg-amber-500/15 text-amber-300',
    dot: 'bg-amber-400'
  },
  error: {
    border: 'border-rose-500/40',
    badgeBg: 'bg-rose-500/15 text-rose-300',
    dot: 'bg-rose-500'
  },
  info: {
    border: 'border-cyan-500/35',
    badgeBg: 'bg-cyan-500/15 text-cyan-300',
    dot: 'bg-cyan-400'
  }
});

export function createToastNotifier(containerElement) {
  let dismissTimerId = null;

  function hide() {
    if (!containerElement) {
      return;
    }
    containerElement.classList.add('opacity-0', 'translate-y-2', 'pointer-events-none');
    containerElement.classList.remove('opacity-100', 'translate-y-0');
  }

  function show(message, variant = 'info', durationMs = 3200) {
    if (!containerElement) {
      return;
    }

    const palette = VARIANT_STYLES[variant] || VARIANT_STYLES.info;
    const card = containerElement.querySelector('[data-toast-card]');
    const dot = containerElement.querySelector('[data-toast-dot]');
    const label = containerElement.querySelector('[data-toast-message]');

    if (card && dot && label) {
      card.className = `flex items-center gap-3 rounded-xl bg-slate-900/95 backdrop-blur-md px-4 py-3 border ${palette.border} shadow-xl shadow-black/40`;
      dot.className = `h-2.5 w-2.5 shrink-0 rounded-full ${palette.dot}`;
      label.textContent = message;
    }

    containerElement.classList.remove('opacity-0', 'translate-y-2', 'pointer-events-none');
    containerElement.classList.add('opacity-100', 'translate-y-0');

    if (dismissTimerId) {
      clearTimeout(dismissTimerId);
    }
    dismissTimerId = setTimeout(hide, durationMs);
  }

  return Object.freeze({ show, hide });
}
