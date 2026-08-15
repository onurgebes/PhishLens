import { AnalyzeRequest, AnalyzeResponse, HealthResponse, ErrorResponse } from '../types/api';

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://127.0.0.1:8000';

class ApiError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ApiError';
  }
}

async function handleResponse(response: Response): Promise<any> {
  if (!response.ok) {
    let errorMessage = 'An error occurred while making the request';
    try {
      const errorData: ErrorResponse = await response.json();
      errorMessage = errorData.detail || errorMessage;
    } catch {
      errorMessage = `HTTP error! status: ${response.status}`;
    }
    throw new ApiError(errorMessage);
  }
  return response.json();
}

export const api = {
  async analyzeRaw(rawEmail: string): Promise<AnalyzeResponse> {
    const request: AnalyzeRequest = { raw_email: rawEmail };
    
    const response = await fetch(`${API_BASE_URL}/api/analyze/raw`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(request),
    });

    return handleResponse(response);
  },

  async healthCheck(): Promise<HealthResponse> {
    const response = await fetch(`${API_BASE_URL}/health`);
    return handleResponse(response);
  },
};

export { ApiError };
