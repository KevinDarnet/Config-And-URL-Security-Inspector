/** @type {import('tailwindcss').Config} */
const projectRoot = import.meta.dirname || '.';

export default {
  darkMode: 'class',
  content: [
    `${projectRoot}/index.html`,
    `${projectRoot}/src/**/*.js`
  ],
  theme: {
    extend: {
      fontFamily: {
        sans: [
          'Inter',
          'ui-sans-serif',
          'system-ui',
          '-apple-system',
          'BlinkMacSystemFont',
          '"Segoe UI"',
          'Roboto',
          'sans-serif'
        ],
        mono: [
          '"JetBrains Mono"',
          '"Fira Code"',
          'ui-monospace',
          'SFMono-Regular',
          'Menlo',
          'Monaco',
          'Consolas',
          'monospace'
        ]
      },
      boxShadow: {
        'argon': '0 10px 30px -10px rgba(0, 0, 0, 0.55)',
        'argon-glow': '0 0 0 1px rgba(34, 211, 238, 0.25), 0 8px 24px -6px rgba(8, 145, 178, 0.28)'
      }
    }
  },
  plugins: []
};
