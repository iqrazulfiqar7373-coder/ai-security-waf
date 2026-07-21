// src/types/security.ts

// ═══════════════════════════════════════════════════════════════════════
// THREAT CATEGORIES
// ═══════════════════════════════════════════════════════════════════════
export enum ThreatCategory {
  SQL_INJECTION = 'SQL_INJECTION',
  NOSQL_INJECTION = 'NOSQL_INJECTION',
  XSS = 'XSS',
  COMMAND_INJECTION = 'COMMAND_INJECTION',
  PATH_TRAVERSAL = 'PATH_TRAVERSAL',
  SSTI = 'SSTI',
  XXE = 'XXE',
  DESERIALIZATION = 'DESERIALIZATION',
  PROMPT_INJECTION = 'PROMPT_INJECTION',
  DELIMITER_SMUGGLING = 'DELIMITER_SMUGGLING',
  JAILBREAK = 'JAILBREAK',
  ENCODING_EVASION = 'ENCODING_EVASION',
  SYSTEM_EXTRACTION = 'SYSTEM_EXTRACTION',
}

// ═══════════════════════════════════════════════════════════════════════
// THREAT SEVERITY
// ═══════════════════════════════════════════════════════════════════════
export enum ThreatSeverity {
  CRITICAL = 'CRITICAL',
  HIGH = 'HIGH',
  MEDIUM = 'MEDIUM',
  LOW = 'LOW',
}

// ═══════════════════════════════════════════════════════════════════════
// THREAT MATCH — result of a single rule/layer detection
// ═══════════════════════════════════════════════════════════════════════
export interface ThreatMatch {
  id: string;
  category: ThreatCategory;
  severity: ThreatSeverity;
  pattern: string;
  matchedPayload: string;
  description: string;
  timestamp: number;
  layer: 'RULE_ENGINE' | 'ENTROPY' | 'EMBEDDING' | string;
}

// ═══════════════════════════════════════════════════════════════════════
// SCAN REQUEST — what the client sends to /api/scan
// ═══════════════════════════════════════════════════════════════════════
export interface ScanRequest {
  payload: string;
  sourceIp?: string;
  timestamp?: number;
  checkOutput?: string;
}

// ═══════════════════════════════════════════════════════════════════════
// AI ANALYSIS — summarized verdict shown in the dashboard
// ═══════════════════════════════════════════════════════════════════════
export interface AIAnalysis {
  intent: 'MALICIOUS' | 'BENIGN' | 'SUSPICIOUS';
  confidence: number;
  reasoning: string;
}

// ═══════════════════════════════════════════════════════════════════════
// SCAN RESPONSE — what /api/scan returns to the client
// ═══════════════════════════════════════════════════════════════════════
export interface ScanResponse {
  id: string;
  blocked: boolean;
  threats: ThreatMatch[];
  reason?: string;
  normalizedPayload?: string;
  processingTime: number;
  aiAnalysis?: AIAnalysis;
}

// ═══════════════════════════════════════════════════════════════════════
// SECURITY EVENT — a single row in the live threat log
// ═══════════════════════════════════════════════════════════════════════
export interface SecurityEvent {
  id: string;
  type: 'BLOCK' | 'ALLOW';
  payload: string;
  normalizedPayload: string;
  threats: ThreatMatch[];
  sourceIp: string;
  timestamp: number;
  aiConfidence?: number;
}