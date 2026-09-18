import { useState } from 'react'

export default function ScanForm({ onScan, error }) {
  const [targetUrl, setTargetUrl] = useState('')
  const [confirmUrl, setConfirmUrl] = useState('')
  const [authorized, setAuthorized] = useState(false)
  const [validationError, setValidationError] = useState('')

  const handleScan = (e) => {
    e.preventDefault()
    if (targetUrl !== confirmUrl) {
      setValidationError('Error: Target URLs do not match')
      return
    }
    if (!authorized) {
      setValidationError('Error: Authorization required')
      return
    }
    setValidationError('')
    onScan(targetUrl, confirmUrl)
  }

  return (
    <div className="scan-form-container">
      <div className="warning-banner">
        ⚠ AUTHORIZED TARGETS ONLY — Only scan systems you own or have explicit written permission to test.
      </div>
      <div className="safe-target-hint">
        Recommended test targets: OWASP Juice Shop (docker run -p 3000:3000 bkimminich/juice-shop) or DVWA
      </div>
      
      {(error || validationError) && (
        <div className="error-message">
          &gt; {error || validationError}
        </div>
      )}

      <form onSubmit={handleScan}>
        <div className="form-group">
          <span style={{ color: 'var(--neon-green)', marginRight: '10px' }}>&gt; TARGET:_</span>
          <input
            type="text"
            className="terminal-input"
            value={targetUrl}
            onChange={(e) => setTargetUrl(e.target.value)}
            placeholder="http://localhost:3000"
            required
          />
        </div>
        
        <div className="form-group">
          <span style={{ color: 'var(--neon-green)', marginRight: '10px' }}>&gt; CONFIRM TARGET:_</span>
          <input
            type="text"
            className="terminal-input"
            value={confirmUrl}
            onChange={(e) => setConfirmUrl(e.target.value)}
            placeholder="http://localhost:3000"
            required
          />
        </div>

        <div className="checkbox-group" onClick={() => setAuthorized(!authorized)}>
          <input
            type="checkbox"
            checked={authorized}
            onChange={() => {}}
            required
          />
          <label>I confirm I own this target or have explicit written authorization to test it</label>
        </div>

        <button 
          type="submit" 
          className="btn-scan"
          disabled={!targetUrl || targetUrl !== confirmUrl || !authorized}
        >
          &gt; INITIATE SCAN
        </button>
      </form>
    </div>
  )
}
