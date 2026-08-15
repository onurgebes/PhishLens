import { useState } from 'react';
import { EmailInput } from '../components/EmailInput';
import { RiskScore } from '../components/RiskScore';
import { FindingsList } from '../components/FindingsList';
import { IocTable } from '../components/IocTable';
import { ParsedEmail } from '../components/ParsedEmail';
import { LoadingState } from '../components/LoadingState';
import { ErrorMessage } from '../components/ErrorMessage';
import { api, ApiError } from '../services/api';
import { AnalyzeResponse } from '../types/api';

export function Dashboard() {
  const [rawEmail, setRawEmail] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<AnalyzeResponse | null>(null);

  const handleAnalyze = async () => {
    if (!rawEmail.trim()) return;

    setIsLoading(true);
    setError(null);
    setResult(null);

    try {
      const response = await api.analyzeRaw(rawEmail);
      setResult(response);
    } catch (err) {
      if (err instanceof ApiError) {
        setError(err.message);
      } else {
        setError('An unexpected error occurred. Please try again.');
      }
    } finally {
      setIsLoading(false);
    }
  };

  const handleDismissError = () => {
    setError(null);
  };

  const handleReset = () => {
    setRawEmail('');
    setResult(null);
    setError(null);
  };

  return (
    <div className="min-h-screen bg-cyber-black">
      {/* Header */}
      <header className="bg-cyber-dark border-b border-cyber-gray">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
          <div className="flex items-center justify-between">
            <div>
              <h1 className="text-3xl font-bold text-white">PhishLens</h1>
              <p className="text-cyber-light mt-1">Email Phishing Analysis Platform</p>
            </div>
            {result && (
              <button
                onClick={handleReset}
                className="px-4 py-2 bg-cyber-gray hover:bg-cyber-light text-white rounded-lg transition-colors"
              >
                Analyze New Email
              </button>
            )}
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {error && <ErrorMessage message={error} onDismiss={handleDismissError} />}

        {!result ? (
          <div className="max-w-4xl mx-auto">
            <div className="bg-cyber-dark border border-cyber-gray rounded-lg p-6">
              <h2 className="text-xl font-bold text-white mb-6">Analyze Email</h2>
              <EmailInput
                value={rawEmail}
                onChange={setRawEmail}
                onAnalyze={handleAnalyze}
                isLoading={isLoading}
              />
            </div>

            {isLoading && <LoadingState />}
          </div>
        ) : (
          <div className="space-y-6">
            <RiskScore riskScore={result.risk_score} />
            
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <FindingsList findings={result.findings} />
              <IocTable iocs={result.iocs} />
            </div>
            
            <ParsedEmail parsedEmail={result.parsed_email} />
          </div>
        )}
      </main>

      {/* Footer */}
      <footer className="bg-cyber-dark border-t border-cyber-gray mt-12">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
          <p className="text-center text-cyber-light text-sm">
            PhishLens - Email Phishing Analysis Platform
          </p>
        </div>
      </footer>
    </div>
  );
}
