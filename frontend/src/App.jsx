import { useState, useRef, useEffect } from 'react'
import './App.css'

function App() {
  const [messages, setMessages] = useState([])
  const [input, setInput] = useState('')
  const [loading, setLoading] = useState(false)
  const messagesEndRef = useRef(null)
  const convId = useRef(`session-${Date.now()}`)

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }

  useEffect(() => {
    scrollToBottom()
  }, [messages, loading])

  const handleSubmit = async (e) => {
    e.preventDefault()
    if (!input.trim() || loading) return

    const userMessage = input.trim()
    setInput('')
    setMessages(prev => [...prev, { type: 'user', text: userMessage }])
    setLoading(true)

    try {
      const res = await fetch('/v1/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          conversation_id: convId.current,
          message: userMessage,
          attachments: null
        })
      })
      const data = await res.json()
      setMessages(prev => [...prev, { type: 'response', data }])
    } catch (err) {
      setMessages(prev => [...prev, { type: 'error', text: err.message }])
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="main-layout">
      <header className="header">
        <h1>🛡️ Prompt Shield</h1>
        <p>Test prompts against the injection defense system</p>
      </header>

      <div className="messages-area">
        {messages.length === 0 && (
          <div className="empty">
            <span className="empty-icon">💬</span>
            <p>Enter a prompt to analyze</p>
          </div>
        )}

        {messages.map((msg, i) => (
          <Message key={i} message={msg} />
        ))}

        {loading && (
          <div className="loading">
            <span></span><span></span><span></span>
          </div>
        )}

        <div ref={messagesEndRef} />
      </div>

      <form className="composer" onSubmit={handleSubmit}>
        <input
          type="text"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          placeholder="Enter a prompt to analyze..."
          disabled={loading}
          autoFocus
        />
        <button type="submit" disabled={loading || !input.trim()}>
          Analyze
        </button>
      </form>
    </div>
  )
}

function Message({ message }) {
  if (message.type === 'user') {
    return <div className="bubble user">{message.text}</div>
  }

  if (message.type === 'error') {
    return <div className="bubble error">❌ {message.text}</div>
  }

  const { data } = message
  const riskClass = data.risk_score <= 30 ? 'low' : data.risk_score <= 60 ? 'medium' : 'high'

  return (
    <div className="card">
      <div className="card-head">
        <span className={`badge ${data.action}`}>
          {data.action === 'block' && '✗ '}
          {data.action === 'allow' && '✓ '}
          {data.action === 'sanitize' && '⚠ '}
          {data.action}
        </span>
        <span className={`risk ${riskClass}`}>{data.risk_score}/100</span>
      </div>

      <div className="card-body">
        {data.signals?.length > 0 ? (
          <div className="tags">
            {data.signals.map((s, i) => (
              <span key={i} className="tag">
                {s.name.replace(/_/g, ' ')} <b>+{s.weight}</b>
              </span>
            ))}
          </div>
        ) : (
          <p className="safe">✓ No threats detected</p>
        )}

        {data.obfuscation_flags?.semantic_danger_detected && (
          <div className="semantic">
            Matched: <strong>{data.obfuscation_flags.semantic_matched_concept}</strong>
            <span>({Math.round(data.obfuscation_flags.semantic_similarity * 100)}%)</span>
          </div>
        )}
      </div>

      <div className="card-foot">
        <span>{data.classification}</span>
        <span>⚡ {data.latency_ms?.total?.toFixed(1)}ms</span>
      </div>
    </div>
  )
}

export default App
