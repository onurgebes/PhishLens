import { IOC } from '../types/api';
import { useState } from 'react';

interface IocTableProps {
  iocs: IOC[];
}

function getIocTypeColor(iocType: string): string {
  const type = iocType.toLowerCase();
  switch (type) {
    case 'domain':
      return 'bg-blue-500/20 text-blue-400 border-blue-500/50';
    case 'email':
      return 'bg-green-500/20 text-green-400 border-green-500/50';
    case 'url':
      return 'bg-purple-500/20 text-purple-400 border-purple-500/50';
    case 'ip':
      return 'bg-orange-500/20 text-orange-400 border-orange-500/50';
    case 'hash':
      return 'bg-pink-500/20 text-pink-400 border-pink-500/50';
    default:
      return 'bg-cyber-gray text-cyber-light border-cyber-light';
  }
}

export function IocTable({ iocs }: IocTableProps) {
  const [copiedIndex, setCopiedIndex] = useState<number | null>(null);

  if (iocs.length === 0) {
    return (
      <div className="bg-cyber-dark border border-cyber-gray rounded-lg p-6">
        <h2 className="text-xl font-bold text-white mb-4">Indicators of Compromise (IOCs)</h2>
        <p className="text-cyber-light">No IOCs detected.</p>
      </div>
    );
  }

  const copyToClipboard = async (value: string, index: number) => {
    try {
      await navigator.clipboard.writeText(value);
      setCopiedIndex(index);
      setTimeout(() => setCopiedIndex(null), 2000);
    } catch (err) {
      console.error('Failed to copy:', err);
    }
  };

  return (
    <div className="bg-cyber-dark border border-cyber-gray rounded-lg p-6">
      <h2 className="text-xl font-bold text-white mb-4">Indicators of Compromise (IOCs) ({iocs.length})</h2>
      <div className="overflow-x-auto">
        <table className="w-full">
          <thead>
            <tr className="border-b border-cyber-gray">
              <th className="text-left py-3 px-4 text-sm font-semibold text-cyber-light uppercase tracking-wider">Type</th>
              <th className="text-left py-3 px-4 text-sm font-semibold text-cyber-light uppercase tracking-wider">Value</th>
              <th className="text-left py-3 px-4 text-sm font-semibold text-cyber-light uppercase tracking-wider">Sources</th>
              <th className="text-right py-3 px-4 text-sm font-semibold text-cyber-light uppercase tracking-wider">Actions</th>
            </tr>
          </thead>
          <tbody>
            {iocs.map((ioc, index) => (
              <tr key={`${ioc.ioc_type}-${ioc.value}-${index}`} className="border-b border-cyber-gray/50 hover:bg-cyber-black/30">
                <td className="py-3 px-4">
                  <span className={`inline-block px-2 py-1 text-xs font-semibold rounded border ${getIocTypeColor(ioc.ioc_type)}`}>
                    {ioc.ioc_type.toUpperCase()}
                  </span>
                </td>
                <td className="py-3 px-4">
                  <code className="text-cyber-accent font-mono text-sm break-all">{ioc.value}</code>
                </td>
                <td className="py-3 px-4">
                  <div className="flex flex-wrap gap-1">
                    {ioc.sources.map((source, sourceIndex) => (
                      <span key={sourceIndex} className="text-xs text-cyber-light bg-cyber-black/50 px-2 py-1 rounded">
                        {source}
                      </span>
                    ))}
                  </div>
                </td>
                <td className="py-3 px-4 text-right">
                  <button
                    onClick={() => copyToClipboard(ioc.value, index)}
                    className="text-cyber-light hover:text-cyber-accent transition-colors p-1"
                    title="Copy to clipboard"
                  >
                    {copiedIndex === index ? (
                      <svg className="w-5 h-5 text-cyber-success" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                      </svg>
                    ) : (
                      <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                      </svg>
                    )}
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
