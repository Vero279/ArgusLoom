/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        base: 'var(--bg-base)',
        surface: 'var(--bg-surface)',
        primary: 'var(--text-primary)',
        secondary: 'var(--text-secondary)',
        accent: 'var(--accent-action)',
      },
    },
  },
  plugins: [],
};
