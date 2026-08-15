// API Types based on backend schemas

export interface Attachment {
  filename: string | null;
  content_type: string;
  size_bytes: number;
}

export interface ParsedEmail {
  from_address: string | null;
  to_addresses: string[];
  cc_addresses: string[];
  reply_to: string | null;
  subject: string | null;
  date: string | null;
  message_id: string | null;
  return_path: string | null;
  received_headers: string[];
  authentication_results: string[];
  content_type: string;
  body_plain: string | null;
  body_html: string | null;
  attachments: Attachment[];
  raw_size_bytes: number;
  parse_warnings: string[];
}

export interface IOC {
  ioc_type: string;
  value: string;
  sources: string[];
}

export interface Finding {
  rule_id: string;
  category: string;
  severity: string;
  title: string;
  description: string;
  evidence: Record<string, string | string[] | number | boolean>;
}

export interface ScoreContribution {
  rule_id: string;
  title: string;
  severity: string;
  base_points: number;
  rule_weight: number;
  weighted_points: number;
  dedup_key: string;
  count_before_dedup: number;
}

export interface RiskScore {
  score: number;
  level: string;
  raw_points: number;
  contributions: ScoreContribution[];
  summary: string;
  recommendation: string;
}

export interface AnalyzeResponse {
  parsed_email: ParsedEmail;
  iocs: IOC[];
  findings: Finding[];
  risk_score: RiskScore;
}

export interface AnalyzeRequest {
  raw_email: string;
}

export interface HealthResponse {
  status: string;
  version: string;
}

export interface ErrorResponse {
  detail: string;
}

export type RiskLevel = 'low' | 'medium' | 'high' | 'critical';
export type Severity = 'low' | 'medium' | 'high' | 'critical';
