import { Finding } from '../types/api';

interface FindingsListProps {
  findings: Finding[];
}

function getSeverityColor(severity: string): string {
  switch (severity.toLowerCase()) {
    case 'low':
      return 'bg-cyber-success text-cyber-black';
    case 'medium':
      return 'bg-cyber-warning text-cyber-black';
    case 'high':
      return 'bg-cyber-danger text-white';
    case 'critical':
      return 'bg-cyber-critical text-white';
    default:
      return 'bg-cyber-gray text-cyber-light';
  }
}

function getSeverityBorderColor(severity: string): string {
  switch (severity.toLowerCase()) {
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

export function FindingsList({ findings }: FindingsListProps) {
  if (findings.length === 0) {
    return (
      <div className="bg-cyber-dark border border-cyber-gray rounded-lg p-6">
        <h2 className="text-xl font-bold text-white mb-4">Findings</h2>
        <p className="text-cyber-light">No findings detected.</p>
      </div>
    );
  }

  return (
    <div className="bg-cyber-dark border border-cyber-gray rounded-lg p-6">
      <h2 className="text-xl font-bold text-white mb-4">Findings ({findings.length})</h2>
      <div className="space-y-4">
        {findings.map((finding, index) => (
          <div
            key={`${finding.rule_id}-${index}`}
            className={`bg-cyber-black/50 border-l-4 ${getSeverityBorderColor(finding.severity)} rounded-r-lg p-4`}
          >
            <div className="flex items-start justify-between mb-2">
              <div>
                <span className={`inline-block px-2 py-1 text-xs font-semibold rounded ${getSeverityColor(finding.severity)} mb-2`}>
                  {finding.severity.toUpperCase()}
                </span>
                <h3 className="text-lg font-semibold text-white">{finding.title}</h3>
              </div>
              <span className="text-xs text-cyber-light font-mono">{finding.rule_id}</span>
            </div>
            
            <p className="text-cyber-light mb-3">{finding.description}</p>
            
            <div className="text-xs text-cyber-light">
              <span className="font-medium">Category:</span> {finding.category}
            </div>

            {Object.keys(finding.evidence).length > 0 && (
              <details className="mt-3">
                <summary className="cursor-pointer text-sm text-cyber-accent hover:text-blue-400">
                  View Evidence
                </summary>
                <div className="mt-2 bg-cyber-dark rounded p-3 text-sm">
                  <pre className="text-cyber-light whitespace-pre-wrap font-mono">
                    {JSON.stringify(finding.evidence, null, 2)}
                  </pre>
                </div>
              </details>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
