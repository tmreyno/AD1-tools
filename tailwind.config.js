/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        // Background colors
        bg: {
          DEFAULT: '#0f1419',
          panel: '#161b22',
          card: '#1c2128',
          hover: '#21262d',
        },
        // Border colors
        border: {
          DEFAULT: '#30363d',
          muted: '#21262d',
        },
        // Text colors
        txt: {
          DEFAULT: '#e6edf3',
          muted: '#8b949e',
          faint: '#6e7681',
        },
        // Accent colors
        accent: {
          DEFAULT: '#2f81f7',
          soft: 'rgba(47, 129, 247, 0.15)',
        },
        // Status colors
        success: {
          DEFAULT: '#3fb950',
          soft: 'rgba(63, 185, 80, 0.15)',
        },
        warning: {
          DEFAULT: '#d29922',
          soft: 'rgba(210, 153, 34, 0.15)',
        },
        error: {
          DEFAULT: '#f85149',
          soft: 'rgba(248, 81, 73, 0.15)',
        },
        // Container type colors
        type: {
          ad1: '#2f81f7',
          e01: '#3fb950',
          l01: '#d29922',
          raw: '#a371f7',
          ufed: '#38b6ff',
          archive: '#ff7b72',
          tar: '#ffa657',
        },
      },
      fontFamily: {
        sans: ['Inter', '-apple-system', 'BlinkMacSystemFont', 'Segoe UI', 'sans-serif'],
        mono: ['JetBrains Mono', 'ui-monospace', 'SFMono-Regular', 'Menlo', 'monospace'],
      },
      fontSize: {
        '2xs': ['10px', '14px'],
        xs: ['11px', '16px'],
        sm: ['12px', '18px'],
        base: ['13px', '20px'],
        lg: ['15px', '22px'],
        xl: ['18px', '26px'],
        '2xl': ['22px', '30px'],
      },
      borderRadius: {
        DEFAULT: '6px',
        lg: '10px',
      },
      spacing: {
        '4.5': '18px',
        '11': '44px',
      },
      animation: {
        'pulse-slow': 'pulse 1s ease-in-out infinite',
        'spin-slow': 'spin 1s linear infinite',
        'indeterminate': 'indeterminate 1.5s ease-in-out infinite',
      },
      keyframes: {
        indeterminate: {
          '0%': { transform: 'translateX(-100%)' },
          '100%': { transform: 'translateX(100%)' },
        },
      },
    },
  },
  plugins: [],
}

