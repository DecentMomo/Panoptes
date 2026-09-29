import { Link, useParams } from "react-router-dom"
import { useQuery } from "@tanstack/react-query"

import { getScan, listFindings } from "@/api/scans"
import type { ScanDetail } from "@/types"
import { Badge } from "@/components/ui/badge"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"

const SEVERITIES = ["critical", "high", "medium", "low", "info"]

function PartialBanner({ scan }: { scan: ScanDetail }) {
  const missed = scan.scanner_runs.filter((run) => run.status !== "completed")
  const kept = scan.scanner_runs.filter((run) => run.status === "completed")
  const why = missed
    .map((run) => `${run.tool} ${run.status === "timeout" ? "timed out" : "failed"}`)
    .join(", ")
  const shown = kept.map((run) => run.tool).join(" and ")
  return (
    <p className="text-sm">
      Partial results: {why || "a scanner did not finish"}.
      {shown ? ` Findings from ${shown} are shown.` : ""}
    </p>
  )
}

export function ScanPage() {
  const { scanId } = useParams()
  const id = Number(scanId)
  const scan = useQuery({
    queryKey: ["scan", id],
    queryFn: () => getScan(id),
    enabled: Number.isFinite(id),
    refetchInterval: (query) => {
      const status = query.state.data?.status
      return status === "queued" || status === "running" ? 2000 : false
    },
  })
  const findings = useQuery({
    queryKey: ["findings", id],
    queryFn: () => listFindings(id),
    enabled: scan.data?.status === "completed" || scan.data?.status === "partial",
  })

  return (
    <main className="mx-auto flex min-h-svh w-full max-w-5xl flex-col gap-6 p-6">
      <header>
        <p className="text-sm text-muted-foreground">
          <Link className="underline underline-offset-4" to="/">
            Projects
          </Link>
        </p>
        <h1 className="text-2xl font-medium">{scan.data?.source_name ?? "Scan"}</h1>
      </header>

      {scan.isPending ? (
        <p className="text-sm text-muted-foreground">Loading scan…</p>
      ) : scan.isError || !scan.data ? (
        <p className="text-sm text-destructive">Could not load this scan.</p>
      ) : (
        <>
          <div className="flex flex-wrap items-center gap-2">
            <Badge variant={scan.data.status === "failed" ? "destructive" : "secondary"}>
              {scan.data.status}
            </Badge>
            {SEVERITIES.map((severity) => (
              <Badge key={severity} variant="outline">
                {severity} {scan.data.severity_counts[severity] ?? 0}
              </Badge>
            ))}
          </div>
          {scan.data.status === "partial" ? <PartialBanner scan={scan.data} /> : null}
          {scan.data.error_message ? (
            <p className="text-sm text-destructive">{scan.data.error_message}</p>
          ) : null}
          <div className="flex flex-col gap-2">
            {scan.data.scanner_runs.map((run) => (
              <Card key={run.id}>
                <CardHeader>
                  <CardTitle className="capitalize">{run.tool}</CardTitle>
                </CardHeader>
                <CardContent className="text-sm text-muted-foreground">
                  {run.status}
                  {run.tool_version ? ` · ${run.tool_version}` : ""}
                  {run.finding_count ? ` · ${run.finding_count} findings` : ""}
                  {run.duration_ms != null ? ` · ${run.duration_ms} ms` : ""}
                  {run.error_message ? ` · ${run.error_message}` : ""}
                </CardContent>
              </Card>
            ))}
          </div>
          {findings.data && findings.data.length > 0 ? (
            <div className="overflow-x-auto rounded-lg border border-border">
              <table className="w-full text-left text-sm">
                <thead className="border-b border-border text-muted-foreground">
                  <tr>
                    <th className="px-3 py-2 font-medium">Severity</th>
                    <th className="px-3 py-2 font-medium">Rule</th>
                    <th className="px-3 py-2 font-medium">Location</th>
                    <th className="px-3 py-2 font-medium">Tools</th>
                    <th className="px-3 py-2 font-medium">OWASP</th>
                    <th className="px-3 py-2 font-medium">Title</th>
                  </tr>
                </thead>
                <tbody>
                  {findings.data.map((finding) => (
                    <tr key={finding.id} className="border-b border-border last:border-0">
                      <td className="px-3 py-2">{finding.severity}</td>
                      <td className="px-3 py-2">{finding.rule_id}</td>
                      <td className="px-3 py-2">
                        {finding.file_path}:{finding.line_start}
                      </td>
                      <td className="px-3 py-2">{finding.source_tools.join(", ")}</td>
                      <td className="px-3 py-2">{finding.owasp_category ?? "—"}</td>
                      <td className="px-3 py-2">{finding.title}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : scan.data.status === "completed" || scan.data.status === "partial" ? (
            <p className="text-sm text-muted-foreground">No findings.</p>
          ) : null}
        </>
      )}
    </main>
  )
}
