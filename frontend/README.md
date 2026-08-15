# PhishLens Frontend

Modern React frontend for the PhishLens email phishing analysis platform.

## Setup

1. Install dependencies:
```bash
npm install
```

2. Create environment file:
```bash
cp .env.example .env
```

3. Configure API URL in `.env`:
- For local development: `VITE_API_BASE_URL=http://127.0.0.1:8000`
- For production: `VITE_API_BASE_URL=https://phishlens-eight.vercel.app`

## Development

Run the development server:
```bash
npm run dev
```

The frontend will be available at `http://localhost:5173`

## Build

Build for production:
```bash
npm run build
```

## Features

- **Email Analysis**: Paste raw email content for phishing analysis
- **Risk Scoring**: Visual risk score with severity levels (LOW, MEDIUM, HIGH, CRITICAL)
- **Findings Display**: Detailed security findings with severity indicators
- **IOC Extraction**: Extracted indicators of compromise with copy-to-clipboard functionality
- **Email Parsing**: Complete email metadata display
- **Responsive Design**: Works on desktop, tablet, and mobile devices
- **Dark Theme**: Professional cybersecurity/SOC-inspired design

## Technology Stack

- React 18
- TypeScript
- Vite
- Tailwind CSS
