import { AnalyzeResponse } from '../types';
import { useState } from 'react';

interface Props {
    response: AnalyzeResponse | null;
}

const ACTION_STYLES = {
    allow: 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30',
    reprompt: 'bg-amber-500/20 text-amber-400 border-amber-500/30',
    sanitize: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
    block: 'bg-red-500/20 text-red-400 border-red-500/30',
};

const ACTION_LABELS = {
    allow: '✅ ALLOW',
    reprompt: '⚠️ REPROMPT',
    sanitize: '🔵 SANITIZE',
    block: '🛑 BLOCK',
};

export default function DecisionPanel({ response }: Props) {
    const [showRaw, setShowRaw] = useState(false);

    if (!response) {
        return (
            <div className="p-6 text-center text-slate-500">
                <div className="w-16 h-16 mx-auto mb-4 rounded-full bg-slate-800 flex items-center justify-center">
                    <span className="text-2xl">🔍</span>
                </div>
                <p>Send a message to see the analysis</p>
            </div>
        );
    }

    const { action, classification, risk_score, signals, obfuscation_flags, sanitized_message, reprompt_message, latency_ms } = response;
    const sortedSignals = [...signals].sort((a, b) => b.weight - a.weight);
    const mlScore = obfuscation_flags.ml_score;

    return (
        <div className="p-4 space-y-4">
            {/* Action Pill */}
            <div className={`text-center py-4 px-6 rounded-xl border-2 ${ACTION_STYLES[action]}`}>
                <div className="text-3xl font-bold">{ACTION_LABELS[action]}</div>
                <div className="text-sm mt-1 opacity-80">
                    Classification: <span className="font-semibold capitalize">{classification}</span>
                </div>
            </div>

            {/* Risk Meter */}
            <div className="glass-card p-4">
                <div className="flex items-center justify-between mb-2">
                    <span className="text-sm font-medium text-slate-300">Risk Score</span>
                    <span className={`text-2xl font-bold ${risk_score >= 60 ? 'text-red-400' : risk_score >= 30 ? 'text-amber-400' : 'text-emerald-400'}`}>
                        {risk_score}
                    </span>
                </div>
                <div className="h-3 bg-slate-700 rounded-full overflow-hidden">
                    <div
                        className={`h-full transition-all duration-500 ${risk_score >= 60 ? 'bg-gradient-to-r from-red-500 to-red-400' : risk_score >= 30 ? 'bg-gradient-to-r from-amber-500 to-amber-400' : 'bg-gradient-to-r from-emerald-500 to-emerald-400'}`}
                        style={{ width: `${risk_score}%` }}
                    />
                </div>
                <div className="flex justify-between text-xs text-slate-500 mt-1">
                    <span>0 (safe)</span>
                    <span>100 (malicious)</span>
                </div>
            </div>

            {/* ML Score */}
            <div className="glass-card p-4">
                <div className="flex items-center justify-between">
                    <span className="text-sm font-medium text-slate-300">ML Score</span>
                    {mlScore !== null ? (
                        <span className={`text-lg font-bold ${mlScore >= 0.7 ? 'text-red-400' : mlScore >= 0.4 ? 'text-amber-400' : 'text-emerald-400'}`}>
                            {(mlScore * 100).toFixed(1)}%
                        </span>
                    ) : (
                        <span className="text-slate-500 text-sm">Not used</span>
                    )}
                </div>
                {mlScore !== null && (
                    <div className="h-2 bg-slate-700 rounded-full overflow-hidden mt-2">
                        <div
                            className={`h-full transition-all duration-500 ${mlScore >= 0.7 ? 'bg-red-500' : mlScore >= 0.4 ? 'bg-amber-500' : 'bg-emerald-500'}`}
                            style={{ width: `${mlScore * 100}%` }}
                        />
                    </div>
                )}
            </div>

            {/* Why Section */}
            <div className="glass-card p-4">
                <h3 className="text-sm font-semibold text-slate-300 mb-3 flex items-center gap-2">
                    <span>🧠</span> Why this decision?
                </h3>
                <div className="space-y-2 text-sm">
                    <div className="flex justify-between">
                        <span className="text-slate-400">Pivot Detected</span>
                        <span className={obfuscation_flags.pivot_detected ? 'text-red-400 font-medium' : 'text-slate-500'}>
                            {obfuscation_flags.pivot_detected ? 'Yes ⚠️' : 'No'}
                        </span>
                    </div>
                    <div className="flex justify-between">
                        <span className="text-slate-400">History Pressure</span>
                        <span className={obfuscation_flags.history_pressure > 0 ? 'text-amber-400' : 'text-slate-500'}>
                            +{obfuscation_flags.history_pressure}
                        </span>
                    </div>
                    <div className="flex justify-between">
                        <span className="text-slate-400">Benign Context</span>
                        <span className={obfuscation_flags.context_has_benign_context ? 'text-emerald-400' : 'text-slate-500'}>
                            {obfuscation_flags.context_has_benign_context ? 'Yes ✓' : 'No'}
                        </span>
                    </div>
                    <div className="flex justify-between">
                        <span className="text-slate-400">Imperative Structure</span>
                        <span className={obfuscation_flags.context_has_imperative_structure ? 'text-red-400 font-medium' : 'text-slate-500'}>
                            {obfuscation_flags.context_has_imperative_structure ? 'Yes ⚠️' : 'No'}
                        </span>
                    </div>
                    <div className="flex justify-between">
                        <span className="text-slate-400">Reprompt Count</span>
                        <span className={obfuscation_flags.reprompt_count > 0 ? 'text-amber-400' : 'text-slate-500'}>
                            {obfuscation_flags.reprompt_count}
                        </span>
                    </div>
                </div>
            </div>

            {/* Detected Signals */}
            {sortedSignals.length > 0 && (
                <div className="glass-card p-4">
                    <h3 className="text-sm font-semibold text-slate-300 mb-3 flex items-center gap-2">
                        <span>🚨</span> Detected Signals
                    </h3>
                    <div className="space-y-2">
                        {sortedSignals.map((sig, i) => (
                            <div key={i} className="bg-slate-800/50 rounded-lg p-3">
                                <div className="flex items-center justify-between mb-1">
                                    <span className="font-medium text-slate-200 text-sm">{sig.name}</span>
                                    <span className={`text-xs px-2 py-0.5 rounded-full ${sig.weight >= 50 ? 'bg-red-500/20 text-red-400' : sig.weight > 0 ? 'bg-amber-500/20 text-amber-400' : 'bg-slate-600/50 text-slate-400'}`}>
                                        weight: {sig.weight}
                                    </span>
                                </div>
                                <p className="text-xs text-slate-400 truncate" title={sig.evidence}>
                                    "{sig.evidence}"
                                </p>
                            </div>
                        ))}
                    </div>
                </div>
            )}

            {/* Reprompt Message */}
            {reprompt_message && (
                <div className="bg-amber-500/10 border border-amber-500/30 rounded-xl p-4">
                    <h3 className="text-sm font-semibold text-amber-400 mb-2 flex items-center gap-2">
                        <span>💬</span> Suggested Clarification
                    </h3>
                    <p className="text-sm text-amber-200">{reprompt_message}</p>
                </div>
            )}

            {/* Sanitized Message */}
            {sanitized_message && (
                <div className="glass-card p-4">
                    <h3 className="text-sm font-semibold text-blue-400 mb-3 flex items-center gap-2">
                        <span>✂️</span> Sanitized Output
                    </h3>
                    <div className="bg-slate-800 rounded-lg p-3">
                        <p className="text-sm text-slate-200 whitespace-pre-wrap">{sanitized_message}</p>
                    </div>
                </div>
            )}

            {/* Latency */}
            <div className="glass-card p-4">
                <div className="flex items-center justify-between text-sm">
                    <span className="text-slate-400">Total Latency</span>
                    <span className="text-cyan-400 font-mono">{latency_ms.total.toFixed(2)} ms</span>
                </div>
            </div>

            {/* Raw JSON Toggle */}
            <div className="glass-card overflow-hidden">
                <button
                    onClick={() => setShowRaw(!showRaw)}
                    className="w-full px-4 py-3 text-left text-sm text-slate-400 hover:bg-slate-700/30 transition-colors flex items-center justify-between"
                >
                    <span>🔧 Raw JSON</span>
                    <span className={`transition-transform ${showRaw ? 'rotate-180' : ''}`}>▼</span>
                </button>
                {showRaw && (
                    <pre className="p-4 text-xs text-slate-400 overflow-x-auto bg-slate-900/50 max-h-[300px] overflow-y-auto">
                        {JSON.stringify(response, null, 2)}
                    </pre>
                )}
            </div>
        </div>
    );
}
