interface EmailInputProps {
  value: string;
  onChange: (value: string) => void;
  onAnalyze: () => void;
  isLoading: boolean;
}

export function EmailInput({ value, onChange, onAnalyze, isLoading }: EmailInputProps) {
  return (
    <div className="w-full">
      <label htmlFor="email-input" className="block text-sm font-medium text-cyber-light mb-2">
        Raw Email Content
      </label>
      <textarea
        id="email-input"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder="Paste your raw email here...
Example:
From: sender@example.com
To: user@example.com
Subject: Example Email

Email content..."
        className="w-full h-64 px-4 py-3 bg-cyber-dark border border-cyber-gray rounded-lg text-cyber-light placeholder-cyber-gray focus:outline-none focus:ring-2 focus:ring-cyber-accent focus:border-transparent resize-none font-mono text-sm"
        disabled={isLoading}
      />
      <div className="mt-4 flex justify-end">
        <button
          onClick={onAnalyze}
          disabled={isLoading || !value.trim()}
          className="px-6 py-3 bg-cyber-accent hover:bg-blue-600 disabled:bg-cyber-gray disabled:cursor-not-allowed text-white font-medium rounded-lg transition-colors duration-200 flex items-center gap-2"
        >
          {isLoading ? (
            <>
              <svg className="animate-spin h-5 w-5" viewBox="0 0 24 24">
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
              </svg>
              Analyzing...
            </>
          ) : (
            <>
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-6 9l2 2 4-4" />
              </svg>
              Analyze Email
            </>
          )}
        </button>
      </div>
    </div>
  );
}
