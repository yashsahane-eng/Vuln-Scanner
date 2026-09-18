import { useEffect, useRef } from 'react'

export default function Terminal({ lines, isScanning }) {
  const endRef = useRef(null)

  useEffect(() => {
    if (endRef.current) {
      endRef.current.scrollIntoView({ behavior: 'smooth' })
    }
  }, [lines])

  const formatTime = (ts) => {
    const d = new Date(ts)
    return d.toLocaleTimeString('en-US', { hour12: false })
  }

  return (
    <div className="terminal-wrapper">
      <div className="terminal-header">
        ┌─[ SCAN OUTPUT ]──────────────────────────────────────────────────────────────┐
      </div>
      <div className="terminal">
        {lines.map((line, i) => (
          <div key={i} className={`terminal-line ${line.severity}`}>
            <span className="timestamp">[{formatTime(line.ts)}]</span>
            {line.text}
          </div>
        ))}
        {isScanning && (
          <div className="terminal-line system">
            <span className="timestamp">[{formatTime(Date.now())}]</span>
            &gt; <span className="terminal-cursor"></span>
          </div>
        )}
        <div ref={endRef} />
      </div>
    </div>
  )
}
