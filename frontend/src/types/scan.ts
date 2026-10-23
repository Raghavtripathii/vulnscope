export type Language = "python" | "javascript";

export interface ScanRequest {
  code: string;
  language: Language;
  filename?: string;
}

export interface Finding {
  detector: string;
  rule_id: string | null;
  vulnerability_type: string;
  severity: string;
  line_number: number | null;
  message: string;
  code_snippet: string | null;
}

export interface ScanResponse {
  scan_id: number;
  language: string;
  findings: Finding[];
}