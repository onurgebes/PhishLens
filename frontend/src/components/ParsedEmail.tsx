import { ParsedEmail as ParsedEmailType } from '../types/api';

interface ParsedEmailProps {
  parsedEmail: ParsedEmailType;
}

function formatValue(value: string | string[] | null): string {
  if (value === null || value === undefined) return 'N/A';
  if (Array.isArray(value)) {
    return value.length > 0 ? value.join(', ') : 'N/A';
  }
  return value || 'N/A';
}

export function ParsedEmail({ parsedEmail }: ParsedEmailProps) {
  return (
    <div className="bg-cyber-dark border border-cyber-gray rounded-lg p-6">
      <h2 className="text-xl font-bold text-white mb-4">Parsed Email Details</h2>
      
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div className="space-y-3">
          <div>
            <label className="block text-sm font-medium text-cyber-light mb-1">From</label>
            <p className="text-white font-mono text-sm break-all">{formatValue(parsedEmail.from_address)}</p>
          </div>
          
          <div>
            <label className="block text-sm font-medium text-cyber-light mb-1">To</label>
            <p className="text-white font-mono text-sm break-all">{formatValue(parsedEmail.to_addresses)}</p>
          </div>
          
          <div>
            <label className="block text-sm font-medium text-cyber-light mb-1">CC</label>
            <p className="text-white font-mono text-sm break-all">{formatValue(parsedEmail.cc_addresses)}</p>
          </div>
          
          <div>
            <label className="block text-sm font-medium text-cyber-light mb-1">Reply-To</label>
            <p className="text-white font-mono text-sm break-all">{formatValue(parsedEmail.reply_to)}</p>
          </div>
          
          <div>
            <label className="block text-sm font-medium text-cyber-light mb-1">Subject</label>
            <p className="text-white text-sm break-all">{formatValue(parsedEmail.subject)}</p>
          </div>
          
          <div>
            <label className="block text-sm font-medium text-cyber-light mb-1">Date</label>
            <p className="text-white font-mono text-sm">{formatValue(parsedEmail.date)}</p>
          </div>
        </div>
        
        <div className="space-y-3">
          <div>
            <label className="block text-sm font-medium text-cyber-light mb-1">Message-ID</label>
            <p className="text-white font-mono text-sm break-all">{formatValue(parsedEmail.message_id)}</p>
          </div>
          
          <div>
            <label className="block text-sm font-medium text-cyber-light mb-1">Return-Path</label>
            <p className="text-white font-mono text-sm break-all">{formatValue(parsedEmail.return_path)}</p>
          </div>
          
          <div>
            <label className="block text-sm font-medium text-cyber-light mb-1">Content-Type</label>
            <p className="text-white font-mono text-sm">{formatValue(parsedEmail.content_type)}</p>
          </div>
          
          <div>
            <label className="block text-sm font-medium text-cyber-light mb-1">Raw Size</label>
            <p className="text-white font-mono text-sm">{parsedEmail.raw_size_bytes.toLocaleString()} bytes</p>
          </div>
          
          {parsedEmail.attachments && parsedEmail.attachments.length > 0 && (
            <div>
              <label className="block text-sm font-medium text-cyber-light mb-1">Attachments ({parsedEmail.attachments.length})</label>
              <div className="space-y-2">
                {parsedEmail.attachments.map((attachment, index) => (
                  <div key={index} className="bg-cyber-black/50 rounded p-2">
                    <p className="text-white text-sm font-medium">{attachment.filename || 'Unnamed'}</p>
                    <p className="text-cyber-light text-xs">{attachment.content_type} • {attachment.size_bytes.toLocaleString()} bytes</p>
                  </div>
                ))}
              </div>
            </div>
          )}
          
          {parsedEmail.parse_warnings && parsedEmail.parse_warnings.length > 0 && (
            <div>
              <label className="block text-sm font-medium text-cyber-warning mb-1">Parse Warnings</label>
              <div className="space-y-1">
                {parsedEmail.parse_warnings.map((warning, index) => (
                  <p key={index} className="text-cyber-warning text-xs">{warning}</p>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
      
      {parsedEmail.body_plain && (
        <div className="mt-6">
          <label className="block text-sm font-medium text-cyber-light mb-2">Plain Text Body</label>
          <div className="bg-cyber-black/50 rounded-lg p-4 max-h-64 overflow-y-auto">
            <pre className="text-white text-sm whitespace-pre-wrap font-mono">{parsedEmail.body_plain}</pre>
          </div>
        </div>
      )}
      
      {parsedEmail.body_html && (
        <div className="mt-6">
          <label className="block text-sm font-medium text-cyber-light mb-2">HTML Body</label>
          <div className="bg-cyber-black/50 rounded-lg p-4 max-h-64 overflow-y-auto">
            <pre className="text-white text-sm whitespace-pre-wrap font-mono">{parsedEmail.body_html}</pre>
          </div>
        </div>
      )}
      
      {parsedEmail.received_headers && parsedEmail.received_headers.length > 0 && (
        <div className="mt-6">
          <label className="block text-sm font-medium text-cyber-light mb-2">Received Headers ({parsedEmail.received_headers.length})</label>
          <div className="bg-cyber-black/50 rounded-lg p-4 max-h-64 overflow-y-auto">
            {parsedEmail.received_headers.map((header, index) => (
              <div key={index} className="text-cyber-light text-xs font-mono mb-1 pb-1 border-b border-cyber-gray/30 last:border-0">
                {header}
              </div>
            ))}
          </div>
        </div>
      )}
      
      {parsedEmail.authentication_results && parsedEmail.authentication_results.length > 0 && (
        <div className="mt-6">
          <label className="block text-sm font-medium text-cyber-light mb-2">Authentication Results</label>
          <div className="bg-cyber-black/50 rounded-lg p-4">
            {parsedEmail.authentication_results.map((result, index) => (
              <div key={index} className="text-cyber-light text-xs font-mono mb-1">
                {result}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
