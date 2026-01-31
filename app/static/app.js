const promptInput = document.getElementById('promptInput');
const analyzeBtn = document.getElementById('analyzeBtn');
const clearBtn = document.getElementById('clearBtn');
const resultsSection = document.getElementById('resultsSection');

// Elements to update
const actionDisplay = document.getElementById('actionDisplay');
const riskScoreEl = document.getElementById('riskScore');
const gaugeFill = document.getElementById('gaugeFill');
const classificationEl = document.getElementById('classification');
const signalsList = document.getElementById('signalsList');
const obfuscationFlags = document.getElementById('obfuscationFlags');
const latencyBars = document.getElementById('latencyBars');

analyzeBtn.addEventListener('click', analyzePrompt);
clearBtn.addEventListener('click', () => {
    promptInput.value = '';
    resultsSection.classList.add('hidden');
});

async function analyzePrompt() {
    const text = promptInput.value.trim();
    if (!text) return;

    analyzeBtn.disabled = true;
    analyzeBtn.innerHTML = '<span>Analyzing...</span>';

    try {
        const response = await fetch('/v1/analyze', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                conversation_id: `web-${Date.now()}`,
                message: text
            })
        });

        const data = await response.json();
        updateUI(data);
        resultsSection.classList.remove('hidden');

    } catch (error) {
        console.error('Error:', error);
        alert('An error occurred while analyzing the prompt.');
    } finally {
        analyzeBtn.disabled = false;
        analyzeBtn.innerHTML = `
            <span>Analyze Prompt</span>
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M5 12h14M12 5l7 7-7 7"/>
            </svg>
        `;
    }
}

function updateUI(data) {
    // 1. Action & Color
    const action = data.action.toUpperCase();
    actionDisplay.querySelector('.action-text').textContent = action;

    let colorVar = '--primary';
    if (data.classification === 'malicious') colorVar = '--danger';
    else if (data.classification === 'uncertain') colorVar = '--warning';
    else if (data.classification === 'benign') colorVar = '--success';

    document.documentElement.style.setProperty('--current-status-color', `var(${colorVar})`);
    actionDisplay.style.color = `var(${colorVar})`;

    // 2. Risk Score & Gauge
    // Gauge path length is approx 126 for the arc (r=40, semi-circle)
    // Actually path is 126 units length roughly for 180 degrees? 
    // Arc length = pi * r = 3.14 * 40 = 125.6
    const score = data.risk_score;
    riskScoreEl.textContent = score;
    classificationEl.textContent = data.classification;
    classificationEl.style.color = `var(${colorVar})`;

    // Calculate dash offset: 126 total. 0 score = 126 offset (hidden). 100 score = 0 offset (full).
    // offset = 126 - (score / 100 * 126)
    const maxDash = 126;
    const offset = maxDash - (score / 100 * maxDash);
    gaugeFill.style.strokeDashoffset = offset;
    gaugeFill.style.stroke = `var(${colorVar})`;

    // 3. Signals
    signalsList.innerHTML = '';
    if (data.signals && data.signals.length > 0) {
        data.signals.forEach(sig => {
            const div = document.createElement('div');
            div.className = 'signal-item';
            div.innerHTML = `
                <span>${formatSignalName(sig.name)}</span>
                <span class="signal-weight" style="color: var(${colorVar})">+${sig.weight}</span>
            `;
            signalsList.appendChild(div);
        });
    } else {
        signalsList.innerHTML = '<div class="empty-state">No suspicious signals detected</div>';
    }

    // 4. Obfuscation
    obfuscationFlags.innerHTML = '';
    const flags = data.obfuscation_flags || {};
    Object.entries(flags).forEach(([key, value]) => {
        // Only show relevant flags or all with active state
        // Key format: "base64_detected" -> "Base64 Detected"
        if (Array.isArray(value)) return; // Skip arrays/lists for simple grid

        const isActive = value === true;
        const div = document.createElement('div');
        div.className = `flag-item ${isActive ? 'active' : ''}`;
        div.innerHTML = `
            <span class="flag-icon"></span>
            <span>${formatSignalName(key)}</span>
        `;
        obfuscationFlags.appendChild(div);
    });

    // 5. Latency
    latencyBars.innerHTML = '';
    const latency = data.latency_ms || {};
    const maxTime = Math.max(...Object.values(latency), 1); // Avoid div by 0

    Object.entries(latency).forEach(([stage, time]) => {
        if (stage === 'total') return;
        const widthPct = (time / maxTime) * 100;
        const div = document.createElement('div');
        div.className = 'latency-row';
        div.innerHTML = `
            <span class="latency-label">${stage}</span>
            <div class="latency-track">
                <div class="latency-fill" style="width: ${widthPct}%"></div>
            </div>
            <span class="latency-val">${time.toFixed(1)}ms</span>
        `;
        latencyBars.appendChild(div);
    });
}

function formatSignalName(str) {
    return str.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
}
