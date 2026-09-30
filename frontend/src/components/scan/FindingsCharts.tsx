import { Bar, BarChart, Cell, Pie, PieChart, XAxis, YAxis } from "recharts"

import type { Finding } from "@/types"

const COLORS = ["#e11d48", "#f97316", "#eab308", "#22c55e", "#38bdf8", "#a78bfa"]

function counts(findings: Finding[], key: (finding: Finding) => string | null) {
  const totals = new Map<string, number>()
  for (const finding of findings) {
    const label = key(finding) ?? "Unmapped"
    totals.set(label, (totals.get(label) ?? 0) + 1)
  }
  return [...totals.entries()]
    .map(([name, value]) => ({ name, value }))
    .sort((left, right) => right.value - left.value)
}

export function FindingsCharts({ findings }: { findings: Finding[] }) {
  const byCwe = counts(findings, (finding) => finding.cwe_id)
  const byOwasp = counts(findings, (finding) => finding.owasp_category)
  return (
    <div className="grid gap-4 lg:grid-cols-2">
      <section className="rounded-lg border border-border p-4">
        <h2 className="mb-3 text-sm font-medium">Findings by CWE</h2>
        {byCwe.length === 0 ? (
          <p className="text-sm text-muted-foreground">No CWE labels.</p>
        ) : (
          <BarChart width={420} height={240} data={byCwe}>
            <XAxis dataKey="name" tick={{ fontSize: 11 }} interval={0} />
            <YAxis allowDecimals={false} width={30} />
            <Bar dataKey="value" fill="currentColor" />
          </BarChart>
        )}
      </section>
      <section className="rounded-lg border border-border p-4">
        <h2 className="mb-3 text-sm font-medium">Findings by OWASP</h2>
        {byOwasp.length === 0 ? (
          <p className="text-sm text-muted-foreground">No OWASP labels.</p>
        ) : (
          <PieChart width={420} height={240}>
            <Pie data={byOwasp} dataKey="value" nameKey="name" outerRadius={80}>
              {byOwasp.map((entry, index) => (
                <Cell key={entry.name} fill={COLORS[index % COLORS.length]} />
              ))}
            </Pie>
          </PieChart>
        )}
      </section>
    </div>
  )
}
