import { useState, useRef, useCallback, useEffect } from 'react'
import Banner from './components/Banner'
import ScanForm from './components/ScanForm'
import ModuleProgress from './components/ModuleProgress'
import Terminal from './components/Terminal'
import ReportView from './components/ReportView'
import './styles/cyberpunk.css'

// Phases: 'idle' | 'scanning' | 'complete' | 'error'
export default function App() {
  const [phase, setPhase] = useState('idle')
  const [target, setTarget] = useState('')
  const [scanId, setScanId] = useState(null)
  const [terminalLines, setTerminalLines] = useState([
    { text: '> VULNSCAN v1.0.0 initialized...', severity: 'system', ts: Date.now() },
    { text: '> Awaiting target acquisition...', severity: 'system', ts: Date.now() + 1 },
    { text: '> Type target URL and confirm authorization to begin.', severity: 'info', ts: Date.now() + 2 },
  ])
  const [moduleProgress, setModuleProgress] = useState({
    port_scan: { progress: 0, status: 'pending', label: 'Port Scanner' },
    headers: { progress: 0, status: 'pending', label: 'Header Check' },
    endpoints: { progress: 0, status: 'pending', label: 'Endpoint Discovery' },
    forms: { progress: 0, status: 'pending', label: 'Form Analysis' },
  })
  const [findings, setFindings] = useState([])
  const [riskScore, setRiskScore] = useState(null)
  const [error, setError] = useState(null)
  const wsRef = useRef(null)

  const addLine = useCallback((text, severity = 'info') => {
    setTerminalLines(prev => [...prev, { text, severity, ts: Date.now() }])
  }, [])

  const startScan = useCallback(async (targetUrl, confirmation) => {
    setError(null)
    setFindings([])
    setRiskScore(null)
    setModuleProgress({
      port_scan: { progress: 0, status: 'pending', label: 'Port Scanner' },
      headers: { progress: 0, status: 'pending', label: 'Header Check' },
      endpoints: { progress: 0, status: 'pending', label: 'Endpoint Discovery' },
      forms: { progress: 0, status: 'pending', label: 'Form Analysis' },
    })
    setTerminalLines([
      { text: `> INITIATING SCAN: ${targetUrl}`, severity: 'system', ts: Date.now() },
      { text: '> Authorization confirmed. Launching modules...', severity: 'system', ts: Date.now() + 1 },
    ])
    
    try {
      const apiBase = (import.meta.env.VITE_API_URL || '').replace(/\/$/, '')
      const res = await fetch(`${apiBase}/api/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target: targetUrl, confirmation })
      })
      
      if (!res.ok) {
        const err = await res.json()
        throw new Error(err.detail || 'Scan initiation failed')
      }
      
      const data = await res.json()
      setScanId(data.scan_id)
      setTarget(targetUrl)
      setPhase('scanning')
      
      // Derive WebSocket connection URL
      let wsUrl
      if (import.meta.env.VITE_WS_URL) {
        const base = import.meta.env.VITE_WS_URL.replace(/\/$/, '')
        wsUrl = `${base}/ws/${data.scan_id}?target=${encodeURIComponent(targetUrl)}`
      } else if (apiBase) {
        const parsed = new URL(apiBase)
        const wsProto = parsed.protocol === 'https:' ? 'wss:' : 'ws:'
        wsUrl = `${wsProto}//${parsed.host}/ws/${data.scan_id}?target=${encodeURIComponent(targetUrl)}`
      } else {
        const wsProto = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
        wsUrl = `${wsProto}//${window.location.host}/ws/${data.scan_id}?target=${encodeURIComponent(targetUrl)}`
      }

      const ws = new WebSocket(wsUrl)
      wsRef.current = ws
      
      ws.onmessage = (event) => {
        const msg = JSON.parse(event.data)
        
        // Add to terminal
        if (msg.message) {
          setTerminalLines(prev => [...prev, {
            text: `> ${msg.message}`,
            severity: msg.severity || 'info',
            ts: Date.now()
          }])
        }
        
        // Update module progress
        if (msg.type === 'progress' && msg.data?.progress !== undefined) {
          setModuleProgress(prev => ({
            ...prev,
            [msg.module]: { ...prev[msg.module], progress: msg.data.progress }
          }))
        }
        
        if (msg.type === 'module_start') {
          setModuleProgress(prev => ({
            ...prev,
            [msg.module]: { ...prev[msg.module], status: 'running', progress: 5 }
          }))
        }
        
        if (msg.type === 'module_done') {
          setModuleProgress(prev => ({
            ...prev,
            [msg.module]: { ...prev[msg.module], status: 'done', progress: 100 }
          }))
        }
        
        if (msg.type === 'finding' && msg.data) {
          setFindings(prev => [...prev, msg.data])
        }
        
        if (msg.type === 'complete') {
          setRiskScore(msg.data?.risk_score)
          // Small delay for dramatic effect
          setTimeout(() => setPhase('complete'), 800)
        }
        
        if (msg.type === 'error') {
          setError(msg.message)
          setPhase('error')
        }
      }
      
      ws.onerror = () => {
        setError('WebSocket connection failed')
        setPhase('error')
      }
      
      ws.onclose = () => {
        if (phase === 'scanning') {
          // Don't set error if scan completed normally
        }
      }
      
    } catch (err) {
      setError(err.message)
      addLine(`> ERROR: ${err.message}`, 'critical')
    }
  }, [addLine, phase])

  const resetScan = () => {
    if (wsRef.current) wsRef.current.close()
    setPhase('idle')
    setScanId(null)
    setTarget('')
    setFindings([])
    setRiskScore(null)
    setError(null)
    setTerminalLines([
      { text: '> VULNSCAN v1.0.0 ready.', severity: 'system', ts: Date.now() },
      { text: '> New scan initialized. Awaiting target...', severity: 'info', ts: Date.now() + 1 },
    ])
    setModuleProgress({
      port_scan: { progress: 0, status: 'pending', label: 'Port Scanner' },
      headers: { progress: 0, status: 'pending', label: 'Header Check' },
      endpoints: { progress: 0, status: 'pending', label: 'Endpoint Discovery' },
      forms: { progress: 0, status: 'pending', label: 'Form Analysis' },
    })
  }

  return (
    <div className="app-container">
      <Banner />
      <StatusBar phase={phase} target={target} />
      
      {(phase === 'idle' || phase === 'error') && (
        <ScanForm onScan={startScan} error={error} />
      )}
      
      {(phase === 'scanning' || phase === 'complete') && (
        <>
          <ModuleProgress modules={moduleProgress} />
          <Terminal lines={terminalLines} isScanning={phase === 'scanning'} />
        </>
      )}
      
      {phase === 'complete' && (
        <ReportView
          findings={findings}
          riskScore={riskScore}
          scanId={scanId}
          target={target}
          apiBase={(import.meta.env.VITE_API_URL || '').replace(/\/$/, '')}
          onReset={resetScan}
        />
      )}
    </div>
  )
}

function StatusBar({ phase, target }) {
  const [time, setTime] = useState(new Date().toLocaleTimeString())
  useEffect(() => {
    const t = setInterval(() => setTime(new Date().toLocaleTimeString()), 1000)
    return () => clearInterval(t)
  }, [])
  
  const statusMap = {
    idle: { text: 'AWAITING TARGET', color: 'var(--neon-green)' },
    scanning: { text: 'SCAN IN PROGRESS', color: 'var(--neon-yellow)' },
    complete: { text: 'SCAN COMPLETE', color: 'var(--neon-cyan)' },
    error: { text: 'ERROR', color: 'var(--neon-red)' },
  }
  const status = statusMap[phase] || statusMap.idle
  
  return (
    <div className="status-bar">
      <span className="status-indicator" style={{ color: status.color }}>◉ {status.text}</span>
      {target && <span className="status-target">TARGET: {target}</span>}
      <span className="status-time">{time}</span>
    </div>
  )
}
