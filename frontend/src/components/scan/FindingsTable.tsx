import { useMemo, useState } from "react"
import { Link } from "react-router-dom"

import type { Finding } from "@/types"

const SEVERITY_RANK: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
}

export function FindingsTable({ findings }: { findings: Finding[] }) {
  const [severity, setSeverity] = useState("all")
  const [tool, setTool] = useState("all")
  const [status, setStatus] = useState("all")
  const [pathQuery, setPathQuery] = useState("")
  const [sort, setSort] = useState<"severity" | "path">("severity")
  const tools = [...new Set(findings.flatMap((finding) => finding.source_tools))].sort()
  const statuses = [...new Set(findings.map((finding) => finding.status))].sort()

  const shown = useMemo(() => {
    const filtered = findings.filter((finding) => {
      if (severity !== "all" && finding.severity !== severity) return false
      if (tool !== "all" && !finding.source_tools.includes(tool)) return false
      if (status !== "all" && finding.status !== status) return false
      if (pathQuery && !finding.file_path.toLowerCase().includes(pathQuery.toLowerCase())) {
        return false
      }
      return true
    })
    return filtered.sort((left, right) => {
      if (sort === "path") return left.file_path.localeCompare(right.file_path)
      return (SEVERITY_RANK[left.severity] ?? 9) - (SEVERITY_RANK[right.severity] ?? 9)
    })
  }, [findings, pathQuery, severity, sort, status, tool])

  return (
    <section className="space-y-3">
      <div className="flex flex-wrap gap-2">
        <Select label="Severity" value={severity} onChange={setSeverity} options={["critical", "high", "medium", "low", "info"]} />
        <Select label="Tool" value={tool} onChange={setTool} options={tools} />
        <Select label="Status" value={status} onChange={setStatus} options={statuses} />
        <input
          value={pathQuery}
          onChange={(event) => setPathQuery(event.target.value)}
          placeholder="Search file path"
          className="h-9 rounded-md border border-border bg-background px-3 text-sm"
        />
        <Select label="Sort" value={sort} onChange={(value) => setSort(value as "severity" | "path")} options={["severity", "path"]} includeAll={false} />
      </div>
      {shown.length === 0 ? (
        <p className="text-sm text-muted-foreground">No findings match these filters.</p>
      ) : (
        <div className="overflow-x-auto rounded-lg border border-border">
          <table className="w-full text-left text-sm">
            <thead className="border-b border-border text-muted-foreground">
              <tr>
                <th className="px-3 py-2 font-medium">Severity</th>
                <th className="px-3 py-2 font-medium">Rule</th>
                <th className="px-3 py-2 font-medium">Location</th>
                <th className="px-3 py-2 font-medium">Tools</th>
                <th className="px-3 py-2 font-medium">Status</th>
                <th className="px-3 py-2 font-medium">Title</th>
              </tr>
            </thead>
            <tbody>
              {shown.map((finding) => (
                <tr key={finding.id} className="border-b border-border last:border-0">
                  <td className="px-3 py-2 capitalize">{finding.severity}</td>
                  <td className="px-3 py-2">{finding.rule_id}</td>
                  <td className="px-3 py-2">{finding.file_path}:{finding.line_start}</td>
                  <td className="px-3 py-2">{finding.source_tools.join(", ")}</td>
                  <td className="px-3 py-2">{finding.status.replaceAll("_", " ")}</td>
                  <td className="px-3 py-2">
                    <Link className="underline underline-offset-4" to={`/findings/${finding.id}`}>
                      {finding.title}
                    </Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  )
}

function Select({
  label,
  value,
  onChange,
  options,
  includeAll = true,
}: {
  label: string
  value: string
  onChange: (value: string) => void
  options: string[]
  includeAll?: boolean
}) {
  return (
    <label className="flex items-center gap-2 text-sm">
      {label}
      <select
        value={value}
        onChange={(event) => onChange(event.target.value)}
        className="h-9 rounded-md border border-border bg-background px-2"
      >
        {includeAll ? <option value="all">All</option> : null}
        {options.map((option) => (
          <option key={option} value={option}>
            {option.replaceAll("_", " ")}
          </option>
        ))}
      </select>
    </label>
  )
}
