import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { cleanup, fireEvent, render, screen } from "@testing-library/react"
import { MemoryRouter, Route, Routes } from "react-router-dom"
import { afterEach, describe, expect, it, vi } from "vitest"

import { ExplanationPanel } from "@/components/finding/ExplanationPanel"
import { FixDiff } from "@/components/finding/FixDiff"
import { StatusControls } from "@/components/finding/StatusControls"
import { useExplanation } from "@/components/finding/useExplanation"
import { ComparePage } from "@/pages/ComparePage"
import type { Explanation, Finding, Scan, ScanCompare, StatusHistory } from "@/types"

vi.mock("@/api/findings", () => ({
  requestExplanation: vi.fn(),
  getExplanation: vi.fn(),
  listHistory: vi.fn(),
  updateStatus: vi.fn(),
}))

vi.mock("@/api/scans", () => ({
  listScans: vi.fn(),
  compareScans: vi.fn(),
}))

import { getExplanation, listHistory, requestExplanation } from "@/api/findings"
import { compareScans, listScans } from "@/api/scans"

const malicious = "<script>alert(1)</script>\n**bold**\n[link](javascript:alert(1))"

function explanation(overrides: Partial<Explanation> = {}): Explanation {
  return {
    status: "completed",
    failure_reason: null,
    ai_generated: true,
    model_name: "qwen2.5-coder:7b",
    prompt_version: "v2",
    plain_explanation: "This call executes text.",
    why_it_matters: "An attacker can run code.",
    fixed_code: "parse(value)",
    fix_rationale: "Parse the value instead.",
    ai_confidence: "high",
    latency_ms: 1,
    prompt_tokens: 1,
    completion_tokens: 1,
    updated_at: null,
    ...overrides,
  }
}

function renderPanel(current: Explanation | undefined, onRetry = vi.fn()) {
  render(
    <ExplanationPanel
      originalCode={"keep\nold\nline"}
      explanation={current}
      pending={false}
      failedToStart={false}
      onRetry={onRetry}
    />,
  )
  return onRetry
}

describe("finding explanation rendering", () => {
  afterEach(() => {
    cleanup()
    vi.clearAllMocks()
  })

  it("renders model output as escaped text", () => {
    render(<FixDiff original="safe()" fixed={malicious} />)
    expect(document.body.textContent).toContain(malicious)
    expect(document.querySelector("script")).toBeNull()
    expect(document.querySelector("a")).toBeNull()
    expect(document.querySelector("strong")).toBeNull()
  })

  it("keeps the review warning prominent", () => {
    renderPanel(explanation())
    expect(screen.getByText("AI-generated, requires review")).toBeInTheDocument()
  })

  it.each([
    ["model_unavailable", "The local Ollama model is unavailable."],
    ["timeout", "The local model took too long to respond."],
    ["invalid_response", "The local model returned an invalid response."],
  ] as const)("shows %s and retries", async (reason, message) => {
    const onRetry = renderPanel(explanation({ status: "failed", failure_reason: reason }))
    expect(screen.getByText(message)).toBeInTheDocument()
    fireEvent.click(screen.getByRole("button", { name: "Retry" }))
    expect(onRetry).toHaveBeenCalledOnce()
  })

  it("renders a multi-line fix in order", () => {
    render(<FixDiff original={"keep\nold\nline\n"} fixed={"keep\nnew\nline\n"} />)
    const text = document.body.textContent ?? ""
    expect(text.indexOf("- old")).toBeLessThan(text.indexOf("+ new"))
    expect(text).toContain("keep")
    expect(text).toContain("line")
  })
})

function PollProbe() {
  useExplanation(7)
  return <p>polling</p>
}

describe("explanation polling", () => {
  afterEach(() => {
    cleanup()
    vi.useRealTimers()
    vi.clearAllMocks()
  })

  it.each(["completed", "failed"] as const)("stops after %s", async (finalStatus) => {
    vi.useFakeTimers()
    vi.mocked(requestExplanation).mockResolvedValue(explanation({ status: "running" }))
    vi.mocked(getExplanation).mockResolvedValue(explanation({ status: "running" }))
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    render(
      <QueryClientProvider client={client}>
        <PollProbe />
      </QueryClientProvider>,
    )
    await vi.waitFor(() => expect(getExplanation).toHaveBeenCalled())
    const callsWhileRunning = vi.mocked(getExplanation).mock.calls.length
    await vi.advanceTimersByTimeAsync(2000)
    expect(vi.mocked(getExplanation).mock.calls.length).toBeGreaterThan(callsWhileRunning)

    vi.mocked(getExplanation).mockResolvedValue(
      explanation({
        status: finalStatus,
        failure_reason: finalStatus === "failed" ? "timeout" : null,
      }),
    )
    await vi.advanceTimersByTimeAsync(2000)
    const settled = vi.mocked(getExplanation).mock.calls.length
    await vi.advanceTimersByTimeAsync(6000)
    expect(vi.mocked(getExplanation).mock.calls.length).toBe(settled)
  })
})

function history(overrides: Partial<StatusHistory> = {}): StatusHistory {
  return {
    id: 1,
    finding_id: 9,
    user_id: 3,
    user_email: "ada@example.com",
    from_status: "open",
    to_status: "false_positive",
    reason: "test fixture",
    carried_from_scan_id: 4,
    created_at: "2026-09-30T00:00:00Z",
    ...overrides,
  }
}

describe("status history", () => {
  afterEach(() => {
    cleanup()
    vi.clearAllMocks()
  })

  it("renders a carried-over row with the original email", async () => {
    vi.mocked(listHistory).mockResolvedValue([history()])
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    render(
      <QueryClientProvider client={client}>
        <StatusControls findingId={9} status="false_positive" />
      </QueryClientProvider>,
    )
    expect(await screen.findByText(/carried over from scan 4 · originally by ada@example.com/)).toBeInTheDocument()
    expect(screen.getByText("carried over from scan 4")).toBeInTheDocument()
  })
})

function scan(id: number, status = "completed"): Scan {
  return {
    id,
    project_id: 1,
    status,
    source_type: "zip",
    source_name: `scan-${id}.zip`,
    files_scanned: 1,
    files_skipped: 0,
    error_message: null,
    created_at: "2026-09-30T00:00:00Z",
    started_at: null,
    finished_at: null,
  }
}

function finding(id: number, title: string): Finding {
  return {
    id,
    scan_id: 2,
    fingerprint: String(id).padStart(64, "0"),
    source_tools: ["bandit"],
    rule_id: "B307",
    title,
    description: title,
    severity: "medium",
    confidence: "high",
    file_path: "calc.py",
    line_start: 2,
    line_end: 2,
    code_snippet: "eval(x)",
    snippet_start_line: 1,
    cwe_id: "CWE-95",
    owasp_category: null,
    status: "open",
    status_reason: null,
    created_at: "2026-09-30T00:00:00Z",
  }
}

describe("compare page", () => {
  afterEach(() => {
    cleanup()
    vi.clearAllMocks()
  })

  it("shows the three counts and a partial-scan warning", async () => {
    vi.mocked(listScans).mockResolvedValue([scan(2, "partial"), scan(1)])
    const compared: ScanCompare = {
      base: scan(1),
      head: scan(2, "partial"),
      fixed: [finding(1, "fixed")],
      new: [finding(2, "new"), finding(3, "also new")],
      still_open: [finding(4, "still"), finding(5, "open"), finding(6, "too")],
    }
    vi.mocked(compareScans).mockResolvedValue(compared)
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    render(
      <QueryClientProvider client={client}>
        <MemoryRouter initialEntries={["/projects/1/compare"]}>
          <Routes>
            <Route path="/projects/:projectId/compare" element={<ComparePage />} />
          </Routes>
        </MemoryRouter>
      </QueryClientProvider>,
    )
    expect(await screen.findByText("Fixed (1)")).toBeInTheDocument()
    expect(screen.getByText("New (2)")).toBeInTheDocument()
    expect(screen.getByText("Still Open (3)")).toBeInTheDocument()
    expect(
      screen.getByText(/A partial scan is missing a tool/),
    ).toBeInTheDocument()
  })
})
