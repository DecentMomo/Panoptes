import { useMemo, useState } from "react"
import { Link, useParams } from "react-router-dom"
import { useQuery } from "@tanstack/react-query"

import { compareScans, listScans } from "@/api/scans"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Skeleton } from "@/components/ui/skeleton"
import type { Finding, Scan } from "@/types"

function finished(scan: Scan): boolean {
  return scan.status === "completed" || scan.status === "partial"
}

function FindingList({ title, findings }: { title: string; findings: Finding[] }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>
          {title} ({findings.length})
        </CardTitle>
      </CardHeader>
      <CardContent>
        {findings.length === 0 ? (
          <p className="text-sm text-muted-foreground">None.</p>
        ) : (
          <ul className="space-y-2 text-sm">
            {findings.map((finding) => (
              <li key={finding.id}>
                <Link className="underline underline-offset-4" to={`/findings/${finding.id}`}>
                  {finding.file_path}:{finding.line_start} {finding.rule_id}
                </Link>
                <span className="text-muted-foreground"> · {finding.title}</span>
              </li>
            ))}
          </ul>
        )}
      </CardContent>
    </Card>
  )
}

export function ComparePage() {
  const { projectId } = useParams()
  const id = Number(projectId)
  const scans = useQuery({
    queryKey: ["scans", id],
    queryFn: () => listScans(id),
    enabled: Number.isFinite(id),
  })
  const ready = useMemo(() => (scans.data ?? []).filter(finished), [scans.data])
  const [baseId, setBaseId] = useState<number | null>(null)
  const [headId, setHeadId] = useState<number | null>(null)
  const selectedBase = baseId ?? ready[1]?.id ?? null
  const selectedHead = headId ?? ready[0]?.id ?? null
  const comparable =
    selectedBase !== null && selectedHead !== null && selectedBase !== selectedHead
  const comparison = useQuery({
    queryKey: ["compare", id, selectedBase, selectedHead],
    queryFn: () => compareScans(id, selectedBase as number, selectedHead as number),
    enabled: Number.isFinite(id) && comparable,
  })

  return (
    <main className="mx-auto flex min-h-svh w-full max-w-5xl flex-col gap-6 p-6">
      <header className="space-y-2">
        <Link className="text-sm underline underline-offset-4" to={`/projects/${id}`}>
          Back to project
        </Link>
        <h1 className="text-2xl font-medium">Compare scans</h1>
      </header>

      {scans.isPending ? (
        <Skeleton className="h-24" />
      ) : scans.isError ? (
        <p className="text-sm text-destructive">Could not load scans.</p>
      ) : ready.length < 2 ? (
        <p className="text-sm text-muted-foreground">
          Upload at least two finished scans to compare them.
        </p>
      ) : (
        <div className="flex flex-wrap gap-4">
          <label className="flex flex-col gap-1 text-sm">
            Base
            <select
              className="h-9 rounded-md border border-border bg-background px-2"
              value={selectedBase ?? ""}
              onChange={(event) => setBaseId(Number(event.target.value))}
            >
              {ready.map((scan) => (
                <option key={scan.id} value={scan.id}>
                  #{scan.id} {scan.source_name} ({scan.status})
                </option>
              ))}
            </select>
          </label>
          <label className="flex flex-col gap-1 text-sm">
            Head
            <select
              className="h-9 rounded-md border border-border bg-background px-2"
              value={selectedHead ?? ""}
              onChange={(event) => setHeadId(Number(event.target.value))}
            >
              {ready.map((scan) => (
                <option key={scan.id} value={scan.id}>
                  #{scan.id} {scan.source_name} ({scan.status})
                </option>
              ))}
            </select>
          </label>
        </div>
      )}

      {comparison.data?.base.status === "partial" || comparison.data?.head.status === "partial" ? (
        <p className="rounded-md border border-border bg-muted px-3 py-2 text-sm">
          A partial scan is missing a tool. Findings from that tool can look Fixed even when the
          code did not change.
        </p>
      ) : null}

      {comparison.isPending && comparable ? (
        <Skeleton className="h-40" />
      ) : comparison.isError ? (
        <p className="text-sm text-destructive">Could not compare these scans.</p>
      ) : comparison.data ? (
        <div className="grid gap-4">
          <FindingList title="Fixed" findings={comparison.data.fixed} />
          <FindingList title="New" findings={comparison.data.new} />
          <FindingList title="Still Open" findings={comparison.data.still_open} />
        </div>
      ) : null}
    </main>
  )
}
