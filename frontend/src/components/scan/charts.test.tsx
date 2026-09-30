import { cleanup, render, screen } from "@testing-library/react"
import { MemoryRouter } from "react-router-dom"
import { afterEach, describe, expect, it } from "vitest"

import { FindingsCharts } from "@/components/scan/FindingsCharts"
import { FindingsTable } from "@/components/scan/FindingsTable"
import { SeverityCards } from "@/components/scan/SeverityCards"
import { severityText } from "@/lib/severity"
import type { Finding } from "@/types"

function finding(id: number, cweId: string | null, owasp: string | null): Finding {
  return {
    id,
    scan_id: 1,
    fingerprint: String(id).padStart(64, "0"),
    source_tools: ["bandit"],
    rule_id: "B307",
    title: "eval",
    description: "eval",
    severity: "medium",
    confidence: "high",
    file_path: "calc.py",
    line_start: 2,
    line_end: 2,
    code_snippet: "eval(x)",
    snippet_start_line: 1,
    cwe_id: cweId,
    owasp_category: owasp,
    status: "open",
    status_reason: null,
    created_at: "2026-09-30T00:00:00Z",
  }
}

const FINDINGS = [
  finding(1, "CWE-95", "A03:2025 - Injection"),
  finding(2, "CWE-95", "A03:2025 - Injection"),
  finding(3, "CWE-295", "A07:2025 - Authentication Failures"),
  finding(4, "CWE-327", null),
]

describe("findings charts", () => {
  afterEach(cleanup)

  it("draws one pie segment per distinct OWASP category", () => {
    const { container } = render(<FindingsCharts findings={FINDINGS} />)
    const sectors = container.querySelectorAll(".recharts-pie-sector")
    expect(sectors.length).toBe(3)
  })

  it("draws one bar per distinct CWE", () => {
    const { container } = render(<FindingsCharts findings={FINDINGS} />)
    const bars = container.querySelectorAll(".recharts-bar-rectangle")
    expect(bars.length).toBe(3)
  })

  it("labels every pie slice with its category and count", () => {
    render(<FindingsCharts findings={FINDINGS} />)
    expect(screen.getByText("A03:2025 - Injection")).toBeInTheDocument()
    expect(screen.getByText("A07:2025 - Authentication Failures")).toBeInTheDocument()
    expect(screen.getByText("Unmapped")).toBeInTheDocument()
  })
})

describe("severity colours", () => {
  afterEach(cleanup)

  it("gives each severity its own colour on the cards", () => {
    render(<SeverityCards counts={{ critical: 1, high: 2, medium: 3, low: 4, info: 5 }} />)
    expect(screen.getByText("critical").className).toContain("text-red-400")
    expect(screen.getByText("high").className).toContain("text-red-400")
    expect(screen.getByText("medium").className).toContain("text-amber-400")
    expect(screen.getByText("low").className).toContain("text-yellow-300")
    expect(screen.getByText("info").className).toContain("text-zinc-400")
  })

  it("colours the severity column in the table", () => {
    const rows = [
      { ...finding(1, "CWE-95", null), severity: "critical" },
      { ...finding(2, "CWE-95", null), severity: "low" },
    ]
    render(
      <MemoryRouter>
        <FindingsTable findings={rows} />
      </MemoryRouter>,
    )
    expect(screen.getByRole("cell", { name: "critical" }).className).toContain(
      severityText("critical"),
    )
    expect(screen.getByRole("cell", { name: "low" }).className).toContain(severityText("low"))
  })
})
