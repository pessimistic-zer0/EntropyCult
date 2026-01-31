import { useState, useRef, useEffect, KeyboardEvent } from 'react';
import { AnalyzeResponse, ChatMessage } from './types';
import DecisionPanel from './components/DecisionPanel';
import ChatBubble from './components/ChatBubble';
import PresetButtons from './components/PresetButtons';

// Generate random conversation ID
const generateConvId = () => `demo-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;

export default function App() {
    const [conversationId, setConversationId] = useState(generateConvId());
    const [input, setInput] = useState('');
    const [messages, setMessages] = useState<ChatMessage[]>([]);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState<string | null>(null);
    const [selectedResponse, setSelectedResponse] = useState<AnalyzeResponse | null>(null);
    const chatEndRef = useRef<HTMLDivElement>(null);

    // Auto-scroll to bottom
    useEffect(() => {
        chatEndRef.current?.scrollIntoView({ behavior: 'smooth' });
    }, [messages]);

    // Select latest gateway response
    useEffect(() => {
        const lastGateway = [...messages].reverse().find(m => m.role === 'gateway');
        if (lastGateway?.response) {
            setSelectedResponse(lastGateway.response);
        }
    }, [messages]);

    const handleSend = async () => {
        if (!input.trim() || loading) return;

        const userMessage: ChatMessage = {
            id: crypto.randomUUID(),
            role: 'user',
            content: input.trim(),
            timestamp: new Date(),
        };

        setMessages(prev => [...prev, userMessage]);
        setInput('');
        setLoading(true);
        setError(null);

        try {
            const res = await fetch('/v1/analyze', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    conversation_id: conversationId,
                    message: userMessage.content,
                }),
            });

            if (!res.ok) {
                throw new Error(`API returned ${res.status}`);
            }

            const data: AnalyzeResponse = await res.json();

            const gatewayMessage: ChatMessage = {
                id: crypto.randomUUID(),
                role: 'gateway',
                content: getActionSummary(data),
                response: data,
                timestamp: new Date(),
            };

            setMessages(prev => [...prev, gatewayMessage]);
        } catch (err) {
            setError(err instanceof Error ? err.message : 'Failed to connect to API');
        } finally {
            setLoading(false);
        }
    };

    const handleKeyDown = (e: KeyboardEvent<HTMLTextAreaElement>) => {
        if (e.key === 'Enter' && !e.shiftKey) {
            e.preventDefault();
            handleSend();
        }
    };

    const handleReset = () => {
        setConversationId(generateConvId());
        setMessages([]);
        setSelectedResponse(null);
        setError(null);
        setInput('');
    };

    const handlePreset = (text: string) => {
        setInput(text);
    };

    return (
        <div className="min-h-screen flex flex-col">
            {/* Header */}
            <header className="bg-slate-900/80 backdrop-blur-sm border-b border-slate-800 px-6 py-4 sticky top-0 z-50">
                <div className="max-w-7xl mx-auto flex items-center justify-between">
                    <div className="flex items-center gap-3">
                        <div className="w-10 h-10 rounded-lg bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center">
                            <span className="text-xl">🛡️</span>
                        </div>
                        <div>
                            <h1 className="text-xl font-bold bg-gradient-to-r from-cyan-400 to-blue-500 bg-clip-text text-transparent">
                                EntropyCult Defense Gateway
                            </h1>
                            <p className="text-xs text-slate-400">Prompt Injection Detection Demo</p>
                        </div>
                    </div>
                    <div className="flex items-center gap-4">
                        <div className="text-sm">
                            <span className="text-slate-500">Session: </span>
                            <code className="text-cyan-400 bg-slate-800 px-2 py-1 rounded text-xs">
                                {conversationId.slice(0, 20)}...
                            </code>
                        </div>
                        <button
                            onClick={handleReset}
                            className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-sm font-medium transition-colors"
                        >
                            Reset Session
                        </button>
                    </div>
                </div>
            </header>

            {/* Error banner */}
            {error && (
                <div className="bg-red-500/20 border-b border-red-500/30 px-6 py-3">
                    <div className="max-w-7xl mx-auto flex items-center justify-between">
                        <span className="text-red-400">⚠️ {error}</span>
                        <button onClick={() => setError(null)} className="text-red-400 hover:text-red-300">✕</button>
                    </div>
                </div>
            )}

            {/* Main content */}
            <div className="flex-1 flex flex-col lg:flex-row max-w-7xl mx-auto w-full">
                {/* Left: Conversation Panel */}
                <div className="flex-1 flex flex-col border-r border-slate-800 min-w-0">
                    {/* Preset buttons */}
                    <PresetButtons onSelect={handlePreset} />

                    {/* Chat messages */}
                    <div className="flex-1 overflow-y-auto p-4 space-y-4 min-h-[300px] max-h-[calc(100vh-350px)]">
                        {messages.length === 0 && (
                            <div className="text-center text-slate-500 py-12">
                                <p className="text-lg mb-2">No messages yet</p>
                                <p className="text-sm">Type a message or use a preset above to test the gateway</p>
                            </div>
                        )}
                        {messages.map(msg => (
                            <ChatBubble
                                key={msg.id}
                                message={msg}
                                isSelected={msg.response === selectedResponse}
                                onClick={() => msg.response && setSelectedResponse(msg.response)}
                            />
                        ))}
                        {loading && (
                            <div className="flex items-center gap-2 text-slate-400 p-4">
                                <div className="w-2 h-2 bg-cyan-500 rounded-full animate-pulse" />
                                <span>Analyzing...</span>
                            </div>
                        )}
                        <div ref={chatEndRef} />
                    </div>

                    {/* Input area */}
                    <div className="border-t border-slate-800 p-4">
                        <div className="flex gap-3">
                            <textarea
                                value={input}
                                onChange={e => setInput(e.target.value)}
                                onKeyDown={handleKeyDown}
                                placeholder="Type a message... (Enter to send, Shift+Enter for newline)"
                                className="flex-1 bg-slate-800 border border-slate-700 rounded-lg px-4 py-3 text-slate-100 placeholder-slate-500 resize-none focus:outline-none focus:ring-2 focus:ring-cyan-500/50 focus:border-cyan-500"
                                rows={2}
                                disabled={loading}
                            />
                            <button
                                onClick={handleSend}
                                disabled={loading || !input.trim()}
                                className="px-6 py-3 rounded-lg bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-white font-semibold transition-all disabled:opacity-50 disabled:cursor-not-allowed"
                            >
                                {loading ? '...' : 'Send'}
                            </button>
                        </div>
                    </div>
                </div>

                {/* Right: Decision Details Panel */}
                <div className="lg:w-[420px] flex-shrink-0 overflow-y-auto max-h-[calc(100vh-80px)]">
                    <DecisionPanel response={selectedResponse} />
                </div>
            </div>
        </div>
    );
}

function getActionSummary(response: AnalyzeResponse): string {
    const { action, classification, risk_score } = response;
    switch (action) {
        case 'allow':
            return `✅ ALLOWED — classified as ${classification} (risk: ${risk_score})`;
        case 'reprompt':
            return `⚠️ REPROMPT — needs clarification (risk: ${risk_score})`;
        case 'sanitize':
            return `🔵 SANITIZED — removed suspicious patterns (risk: ${risk_score})`;
        case 'block':
            return `🛑 BLOCKED — detected ${classification} intent (risk: ${risk_score})`;
        default:
            return `Action: ${action}`;
    }
}
