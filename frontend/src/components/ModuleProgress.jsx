export default function ModuleProgress({ modules }) {
  return (
    <div className="progress-container">
      {Object.entries(modules).map(([key, module]) => (
        <ProgressBar key={key} module={module} />
      ))}
    </div>
  )
}

function ProgressBar({ module }) {
  const { progress, status, label } = module
  
  const getStatusIcon = (status) => {
    switch(status) {
      case 'pending': return '⧖'
      case 'running': return '▶'
      case 'done': return '✓'
      default: return '⧖'
    }
  }

  const BAR_WIDTH = 16
  const filled = Math.round((progress / 100) * BAR_WIDTH)
  const barChars = '█'.repeat(filled) + '░'.repeat(BAR_WIDTH - filled)

  return (
    <div className="progress-module">
      <div className={`progress-header ${status}`}>
        <span>{getStatusIcon(status)} {label}</span>
        <span>{status.toUpperCase()}</span>
      </div>
      <div className="progress-bar-container">
        <div className="progress-text">[{barChars}]</div>
        <div className="progress-bar-track" style={{ display: 'none' }}>
          <div 
            className={`progress-bar-fill ${status}`}
            style={{ width: `${progress}%` }}
          />
        </div>
        <div className="progress-text" style={{ minWidth: '40px', textAlign: 'right' }}>
          {Math.round(progress)}%
        </div>
      </div>
    </div>
  )
}
