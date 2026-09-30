import { Bar, BarChart, Cell, Pie, PieChart, XAxis, YAxis } from "recharts"

import type { Finding } from "@/types"

const SLICE_COLORS = ["#38bdf8", "#f87171", "#fbbf24", "#a78bfa", "#34d399", "#fb923c", "#f472b6"]
const BAR_COLOR = "#38bdf8"
const AXIS_COLOR = "#a1a1aa"

// Recharts animates a pie in from nothing and a bar up from zero height. In a
// screenshot or a test the first paint is then empty, so both are static here.
const ANIMATE = false

type Slice = { name: string; value: number }

function counts(findings: Finding[], key: (finding: Finding) => string | null): Slice[] {
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
  // Horizontal bars: CWE ids are long enough to collide on a shared x axis.
  const barHeight = Math.max(160, byCwe.length * 26 + 40)

  return (
    <div className="grid gap-4 lg:grid-cols-2">
      <section className="rounded-lg border border-border p-4">
        <h2 className="mb-3 text-sm font-medium">Findings by CWE</h2>
        {byCwe.length === 0 ? (
          <p className="text-sm text-muted-foreground">No CWE labels.</p>
        ) : (
          <BarChart
            layout="vertical"
            width={420}
            height={barHeight}
            data={byCwe}
            margin={{ top: 4, right: 16, bottom: 4, left: 0 }}
          >
            <XAxis
              type="number"
              allowDecimals={false}
              tick={{ fill: AXIS_COLOR, fontSize: 11 }}
              stroke={AXIS_COLOR}
            />
            <YAxis
              type="category"
              dataKey="name"
              width={88}
              tick={{ fill: AXIS_COLOR, fontSize: 11 }}
              stroke={AXIS_COLOR}
            />
            <Bar dataKey="value" fill={BAR_COLOR} isAnimationActive={ANIMATE} />
          </BarChart>
        )}
      </section>

      <section className="rounded-lg border border-border p-4">
        <h2 className="mb-3 text-sm font-medium">Findings by OWASP</h2>
        {byOwasp.length === 0 ? (
          <p className="text-sm text-muted-foreground">No OWASP labels.</p>
        ) : (
          <div className="flex flex-wrap items-center gap-4">
            <PieChart width={220} height={220}>
              <Pie
                data={byOwasp}
                dataKey="value"
                nameKey="name"
                cx="50%"
                cy="50%"
                innerRadius={48}
                outerRadius={88}
                paddingAngle={1}
                isAnimationActive={ANIMATE}
              >
                {byOwasp.map((slice, index) => (
                  <Cell key={slice.name} fill={SLICE_COLORS[index % SLICE_COLORS.length]} />
                ))}
              </Pie>
            </PieChart>
            <ul className="flex min-w-40 flex-1 flex-col gap-1 text-sm">
              {byOwasp.map((slice, index) => (
                <li key={slice.name} className="flex items-center gap-2">
                  <span
                    aria-hidden="true"
                    className="size-3 shrink-0 rounded-sm"
                    style={{ backgroundColor: SLICE_COLORS[index % SLICE_COLORS.length] }}
                  />
                  <span className="text-muted-foreground">{slice.name}</span>
                  <span className="ml-auto tabular-nums">{slice.value}</span>
                </li>
              ))}
            </ul>
          </div>
        )}
      </section>
    </div>
  )
}
