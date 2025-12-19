/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        brand: {
          50: '#f6f4ff',
          100: '#ede9fe',
          200: '#dcd5fe',
          300: '#c1b4fd',
          400: '#a18afc',
          500: '#7c5bfa',
          600: '#6744f3',
          700: '#5535df',
          800: '#462bb7',
          900: '#3b2694'
        }
      }
    },
  },
  plugins: [],
}
