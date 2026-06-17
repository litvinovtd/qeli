/** @type {import('tailwindcss').Config} */
// Scans the panel templates for utility classes and emits a single static
// stylesheet (../src/web/assets/app.css) so the panel needs NO runtime CDN —
// it works on an air-gapped server reached over an SSH tunnel. Regenerate with
// `npm run build` after editing any template. The theme mirrors the tokens the
// templates rely on (custom colors + brand fonts).
module.exports = {
  content: ['../src/web/templates/**/*.html'],
  theme: {
    extend: {
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'ui-monospace', 'monospace'],
      },
      colors: {
        surface: { DEFAULT: '#080b14', 1: '#111a2e', 2: '#16213e', border: '#21314e' },
        brand: { blue: '#4a9eff', teal: '#16c8b6', green: '#00e676' },
      },
    },
  },
  plugins: [],
};
