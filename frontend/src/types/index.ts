export type User = {
  id: number
  email: string
}

export type Project = {
  id: number
  name: string
  description: string | null
  created_at: string
  latest_scan_status?: string | null
}

export type Scan = {
  id: number
  project_id: number
  status: string
  source_type: string
  source_name: string
  files_scanned: number
  files_skipped: number
  error_message: string | null
  created_at: string
  started_at: string | null
  finished_at: string | null
}

export type ScannerRun = {
  id: number
  tool: string
  status: string
  duration_ms: number | null
  finding_count: number
  error_message: string | null
}

export type ScanDetail = Scan & {
  scanner_runs: ScannerRun[]
  severity_counts: Record<string, number>
}

export type Finding = {
  id: number
  scan_id: number
  fingerprint: string
  source_tools: string[]
  rule_id: string
  title: string
  description: string
  severity: string
  confidence: string
  file_path: string
  line_start: number
  line_end: number
  code_snippet: string
  snippet_start_line: number
  cwe_id: string | null
  owasp_category: string | null
  status: string
  status_reason: string | null
  created_at: string
}
