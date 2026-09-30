import { useEffect } from "react"
import { Link, useParams } from "react-router-dom"
import { useQuery } from "@tanstack/react-query"
import { toast } from "sonner"

import { getScan, listFindings } from "@/api/scans"
import { FindingsCharts } from "@/components/scan/FindingsCharts"
import { FindingsTable } from "@/components/scan/FindingsTable"
import { SeverityCards } from "@/components/scan/SeverityCards"
import { Badge } from "@/components/ui/badge"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Skeleton } from "@/components/ui/skeleton"
import type { ScanDetail } from "@/types"

function PartialBanner({ scan }: { scan: ScanDetail }) {
  const missed = scan.scanner_runs.filter((run) => run.status !== "completed")
  const kept = scan.scanner_runs.filter((run) => run.status === "completed")
  const why = missed
    .map((run) => `${run.tool} ${run.status === "timeout" ? "timed out" : "failed"}`)
    .join(", ")
  const shown = kept.map((run) => run.tool).join(" and ")
  return (
    <p className="rounded-md border border-border bg-muted px-3 py-2 text-sm">
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
  const ready = scan.data?.status === "completed" || scan.data?.status === "partial"
  const findings = useQuery({
    queryKey: ["findings", id],
    queryFn: () => listFindings(id),
    enabled: ready,
  })

  useEffect(() => {
    if (scan.isError) toast.error("Could not load this scan.")
    if (findings.isError) toast.error("Could not load findings.")
  }, [findings.isError, scan.isError])

  return (
    <main className="mx-auto flex min-h-svh w-full max-w-6xl flex-col gap-6 p-6">
      <header className="space-y-2">
        <Link className="text-sm underline underline-offset-4" to="/">
          Projects
        </Link>
        <div className="flex flex-wrap items-center gap-2">
          <h1 className="text-2xl font-medium">{scan.data?.source_name ?? "Scan"}</h1>
          {scan.data ? (
            <Badge variant={scan.data.status === "failed" ? "destructive" : "secondary"}>
              {scan.data.status}
            </Badge>
          ) : null}
        </div>
      </header>

      {scan.isPending ? (
        <div className="grid gap-3 sm:grid-cols-5">
          {Array.from({ length: 5 }, (_, index) => (
            <Skeleton key={index} className="h-24" />
          ))}
        </div>
      ) : scan.isError || !scan.data ? (
        <p className="text-sm text-destructive">Could not load this scan.</p>
      ) : (
        <>
          <SeverityCards counts={scan.data.severity_counts} />
          {scan.data.status === "partial" ? <PartialBanner scan={scan.data} /> : null}
          {scan.data.error_message ? (
            <p className="text-sm text-destructive">{scan.data.error_message}</p>
          ) : null}
          <div className="grid gap-3 md:grid-cols-3">
            {scan.data.scanner_runs.map((run) => (
              <Card key={run.id}>
                <CardHeader>
                  <CardTitle className="capitalize">{run.tool}</CardTitle>
                </CardHeader>
                <CardContent className="text-sm text-muted-foreground">
                  {run.status}
                  {run.finding_count ? ` · ${run.finding_count} findings` : ""}
                  {run.duration_ms != null ? ` · ${run.duration_ms} ms` : ""}
                  {run.error_message ? ` · ${run.error_message}` : ""}
                </CardContent>
              </Card>
            ))}
          </div>
          {findings.isPending && ready ? <Skeleton className="h-64" /> : null}
          {findings.data && findings.data.length > 0 ? (
            <>
              <FindingsCharts findings={findings.data} />
              <FindingsTable findings={findings.data} />
            </>
          ) : ready && findings.data ? (
            <p className="text-sm text-muted-foreground">No findings.</p>
          ) : null}
        </>
      )}
    </main>
  )
}
