import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { cleanup, fireEvent, render, screen } from "@testing-library/react"
import { afterEach, describe, expect, it, vi } from "vitest"

import { ExplanationPanel } from "@/components/finding/ExplanationPanel"
import { FixDiff } from "@/components/finding/FixDiff"
import { useExplanation } from "@/components/finding/useExplanation"
import type { Explanation } from "@/types"

vi.mock("@/api/findings", () => ({
  requestExplanation: vi.fn(),
  getExplanation: vi.fn(),
}))

import { getExplanation, requestExplanation } from "@/api/findings"

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
