# EntropyCult Demo Frontend

A polished React + Vite + Tailwind demo UI for the Prompt Injection Defense Gateway.

## Quick Start

**Prerequisites**: Node.js 18+ and the FastAPI backend running on port 8000.

```bash
# Terminal 1: Start the backend (from project root)
cd /home/zer0/Desktop/EntropyCult
uvicorn app.main:app --port 8000 --reload

# Terminal 2: Start the frontend
cd /home/zer0/Desktop/EntropyCult/frontend
npm install
npm run dev
```

Open http://localhost:3000 in your browser.

## Features

- **Chat Interface**: Multi-turn conversation with the gateway
- **Preset Demos**: Quick test buttons for different scenarios
- **Decision Panel**: Visual breakdown of gateway verdicts
- **Risk Meter**: Color-coded 0-100 risk score
- **ML Score**: Shows model confidence when used
- **Signal List**: Detected patterns sorted by weight
- **Raw JSON**: Collapsible debug view

## Architecture

```
frontend/
├── src/
│   ├── App.tsx              # Main app component
│   ├── main.tsx             # React entry point
│   ├── index.css            # Tailwind + custom styles
│   ├── types.ts             # TypeScript interfaces
│   └── components/
│       ├── DecisionPanel.tsx  # Right panel with analysis
│       ├── ChatBubble.tsx     # Message bubbles
│       └── PresetButtons.tsx  # Demo scenario buttons
├── vite.config.ts           # Vite config with API proxy
├── tailwind.config.js       # Tailwind customization
└── package.json             # Dependencies
```

The Vite dev server proxies `/v1/*` requests to `localhost:8000` so no CORS issues.
