// Types for the API response
export interface Signal {
    name: string;
    weight: number;
    evidence: string;
}

export interface ObfuscationFlags {
    zero_width_removed: boolean;
    mixed_script: boolean;
    scripts_detected: string[];
    base64_detected: boolean;
    url_encoded_detected: boolean;
    multi_turn_enabled: boolean;
    turns_used: number;
    history_pressure: number;
    effective_risk_score: number;
    current_risk_score: number;
    pivot_detected: boolean;
    reprompt_count: number;
    block_count: number;
    ml_score: number | null;
    behavior_repeat_override: number;
    behavior_repeat_exfil: number;
    behavior_high_risk_turns: number;
    behavior_recent_signals: string[];
    context_has_benign_context: boolean;
    context_has_imperative_structure: boolean;
    history_risk_score?: number;
}

export interface LatencyMs {
    history_fetch: number;
    preprocess: number;
    signals_current: number;
    signals_history: number;
    ml?: number;
    sanitize: number;
    policy: number;
    memory_store: number;
    total: number;
}

export interface AnalyzeResponse {
    conversation_id: string;
    action: 'allow' | 'reprompt' | 'sanitize' | 'block';
    classification: 'benign' | 'uncertain' | 'malicious';
    risk_score: number;
    signals: Signal[];
    obfuscation_flags: ObfuscationFlags;
    sanitized_message: string | null;
    reprompt_message: string | null;
    latency_ms: LatencyMs;
}

export interface ChatMessage {
    id: string;
    role: 'user' | 'gateway';
    content: string;
    response?: AnalyzeResponse;
    timestamp: Date;
}
