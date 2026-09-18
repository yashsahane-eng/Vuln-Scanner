import { useState } from 'react'
import RiskScore from './RiskScore'

export default function ReportView({ findings, riskScore, scanId, target, onReset }) {
  const [expandedModules, setExpandedModules] = useState({
    port_scan: true,
    headers: true,
    endpoints: true,
    forms: true
  })

  const toggleModule = (moduleKey) => {
    setExpandedModules(prev => ({
      ...prev,
      [moduleKey]: !prev[moduleKey]
    }))
  }

  const moduleNames = {
    port_scan: 'Port Scanner',
    headers: 'Header Checker',
    endpoints: 'Endpoint Discovery',
    forms: 'Form Checker'
  }

  const stats = {
    total: findings.length,
    critical: findings.filter(f => f.severity === 'critical').length,
    high: findings.filter(f => f.severity === 'high').length,
    medium: findings.filter(f => f.severity === 'medium').length,
    low: findings.filter(f => f.severity === 'low').length,
  }

  // Group findings
  const groupedFindings = findings.reduce((acc, finding) => {
    if (!acc[finding.module]) acc[finding.module] = []
    acc[finding.module].push(finding)
    return acc
  }, {})

  return (
    <div className="report-container">
      <div className="report-header">
        ╔══[ MISSION DEBRIEF: {target} ]═══════════════════════════════╗
      </div>

      <RiskScore riskScore={riskScore} />

      <div className="summary-stats">
        <div className="stat-item">
          <div className="stat-value">{stats.total}</div>
          <div className="stat-label">Total Findings</div>
        </div>
        <div className="stat-item">
          <div className="stat-value critical">{stats.critical}</div>
          <div className="stat-label">Critical</div>
        </div>
        <div className="stat-item">
          <div className="stat-value high">{stats.high}</div>
          <div className="stat-label">High</div>
        </div>
        <div className="stat-item">
          <div className="stat-value medium">{stats.medium}</div>
          <div className="stat-label">Medium</div>
        </div>
        <div className="stat-item">
          <div className="stat-value low">{stats.low}</div>
          <div className="stat-label">Low</div>
        </div>
      </div>

      <div className="findings-section">
        {Object.entries(moduleNames).map(([moduleKey, moduleName]) => {
          const moduleFindings = groupedFindings[moduleKey] || []
          const isExpanded = expandedModules[moduleKey]
          
          return (
            <div key={moduleKey} className="module-section">
              <div className="module-header" onClick={() => toggleModule(moduleKey)}>
                <div className="module-title">
                  {isExpanded ? '▼' : '▶'} {moduleName}
                </div>
                <div className="finding-count-badge">
                  {moduleFindings.length} findings
                </div>
              </div>
              
              {isExpanded && (
                <div className="module-content">
                  {moduleFindings.length === 0 ? (
                    <div style={{ color: 'var(--text-dim)', fontStyle: 'italic' }}>No vulnerabilities detected in this module.</div>
                  ) : (
                    moduleFindings.map((finding, idx) => (
                      <div key={idx} className={`finding-card severity-${finding.severity}`}>
                        <div className="finding-header">
                          <div className="finding-title">{finding.title}</div>
                          <div className={`severity-badge ${finding.severity}`}>
                            {finding.severity}
                          </div>
                        </div>
                        <div className="finding-location">
                          Target: {finding.location}
                        </div>
                        <div className="finding-desc">
                          {finding.description}
                        </div>
                        {finding.recommendation && (
                          <div className="finding-recommendation">
                            <strong>RECOMMENDATION:</strong> {finding.recommendation}
                          </div>
                        )}
                      </div>
                    ))
                  )}
                </div>
              )}
            </div>
          )
        })}
      </div>

      <div className="report-actions">
        {scanId && (
          <>
            <a href={`/api/report/${scanId}/json`} target="_blank" rel="noreferrer" className="download-btn">
              &gt; EXPORT JSON REPORT_
            </a>
            <a href={`/api/report/${scanId}/html`} target="_blank" rel="noreferrer" className="download-btn">
              &gt; EXPORT HTML REPORT_
            </a>
          </>
        )}
        <button onClick={onReset} className="btn-scan" style={{ width: 'auto' }}>
          &gt; INITIATE NEW SCAN_
        </button>
      </div>
    </div>
  )
}
