import { RiskScore as RiskScoreType } from '../types/api';

interface RiskScoreProps {
  riskScore: RiskScoreType;
}

function getRiskColor(level: string): string {
  switch (level.toLowerCase()) {
    case 'low':
      return 'text-cyber-success';
    case 'medium':
      return 'text-cyber-warning';
    case 'high':
      return 'text-cyber-danger';
    case 'critical':
      return 'text-cyber-critical';
    default:
      return 'text-cyber-light';
  }
}

function getRiskBgColor(level: string): string {
  switch (level.toLowerCase()) {
    case 'low':
      return 'bg-cyber-success';
    case 'medium':
      return 'bg-cyber-warning';
    case 'high':
      return 'bg-cyber-danger';
    case 'critical':
      return 'bg-cyber-critical';
    default:
      return 'bg-cyber-gray';
  }
}

function getRiskBorderColor(level: string): string {
  switch (level.toLowerCase()) {
    case 'low':
      return 'border-cyber-success';
    case 'medium':
      return 'border-cyber-warning';
    case 'high':
      return 'border-cyber-danger';
    case 'critical':
      return 'border-cyber-critical';
    default:
      return 'border-cyber-gray';
  }
}

export function RiskScore({ riskScore }: RiskScoreProps) {
  const percentage = Math.min(riskScore.score, 100);
  const riskColor = getRiskColor(riskScore.level);
  const riskBgColor = getRiskBgColor(riskScore.level);
  const riskBorderColor = getRiskBorderColor(riskScore.level);

  return (
    <div className={`bg-cyber-dark border-2 ${riskBorderColor} rounded-lg p-6 mb-6`}>
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-xl font-bold text-white">Risk Score</h2>
        <span className={`text-2xl font-bold ${riskColor} uppercase`}>{riskScore.level}</span>
      </div>
      
      <div className="mb-6">
        <div className="flex items-end justify-between mb-2">
          <span className="text-5xl font-bold text-white">{riskScore.score}</span>
          <span className="text-cyber-light text-lg mb-2">/ 100</span>
        </div>
        <div className="w-full bg-cyber-gray rounded-full h-3">
          <div
            className={`${riskBgColor} h-3 rounded-full transition-all duration-500`}
            style={{ width: `${percentage}%` }}
          ></div>
        </div>
      </div>

      <div className="space-y-4">
        <div className="bg-cyber-black/50 rounded-lg p-4">
          <h3 className="text-sm font-medium text-cyber-light mb-2">Summary</h3>
          <p className="text-white">{riskScore.summary}</p>
        </div>
        
        <div className="bg-cyber-black/50 rounded-lg p-4">
          <h3 className="text-sm font-medium text-cyber-light mb-2">Recommendation</h3>
          <p className="text-white">{riskScore.recommendation}</p>
        </div>
      </div>
    </div>
  );
}
