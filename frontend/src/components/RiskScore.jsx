export default function RiskScore({ riskScore }) {
  if (!riskScore) return null

  const { score, rating, color } = riskScore
  
  const radius = 70
  const circumference = 2 * Math.PI * radius
  const offset = circumference - (score / 100) * circumference

  return (
    <div className="risk-score-container">
      <svg width="180" height="180" style={{ animation: 'risk-glow 2s infinite', color: color }}>
        <circle 
          cx="90" 
          cy="90" 
          r={radius} 
          fill="none" 
          stroke="#1a3a2a" 
          strokeWidth="8" 
        />
        <circle
          cx="90" 
          cy="90" 
          r={radius}
          fill="none"
          stroke={color}
          strokeWidth="8"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          strokeLinecap="round"
          transform="rotate(-90 90 90)"
          style={{ 
            transition: 'stroke-dashoffset 1.5s ease-out' 
          }}
        />
        <text 
          x="90" 
          y="85" 
          textAnchor="middle" 
          fill={color} 
          fontSize="36" 
          fontFamily="var(--font-mono)" 
          fontWeight="bold"
        >
          {Math.round(score)}
        </text>
        <text 
          x="90" 
          y="110" 
          textAnchor="middle" 
          fill={color} 
          fontSize="14" 
          fontFamily="var(--font-mono)"
          letterSpacing="1px"
        >
          {rating}
        </text>
      </svg>
    </div>
  )
}
