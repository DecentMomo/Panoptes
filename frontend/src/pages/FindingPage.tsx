import { Link, useParams } from "react-router-dom"
import { useQuery } from "@tanstack/react-query"

import { getFinding } from "@/api/findings"
import { CodeSnippet } from "@/components/finding/CodeSnippet"
import { ExplanationPanel } from "@/components/finding/ExplanationPanel"
import { ReferenceBadges } from "@/components/finding/ReferenceBadges"
import { StatusControls } from "@/components/finding/StatusControls"
import { useExplanation } from "@/components/finding/useExplanation"
import { Badge } from "@/components/ui/badge"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Skeleton } from "@/components/ui/skeleton"

export function FindingPage() {
  const { findingId } = useParams()
  const id = Number(findingId)
  const finding = useQuery({
    queryKey: ["finding", id],
    queryFn: () => getFinding(id),
    enabled: Number.isFinite(id),
  })
  const { explanation, request, retry } = useExplanation(id)

  return (
    <main className="mx-auto flex min-h-svh w-full max-w-4xl flex-col gap-6 p-6">
      {finding.isPending ? (
        <Skeleton className="h-80" />
      ) : finding.isError || !finding.data ? (
        <p className="text-sm text-destructive">Could not load this finding.</p>
      ) : (
        <>
          <header className="space-y-3">
            <Link className="text-sm underline underline-offset-4" to={`/scans/${finding.data.scan_id}`}>
              Back to scan
            </Link>
            <div className="flex flex-wrap items-center gap-2">
              <h1 className="text-2xl font-medium">{finding.data.title}</h1>
              <Badge variant="outline" className="capitalize">
                {finding.data.severity}
              </Badge>
              <Badge variant="secondary">{finding.data.rule_id}</Badge>
            </div>
            <p className="text-sm text-muted-foreground">
              {finding.data.file_path}:{finding.data.line_start}
            </p>
            <ReferenceBadges cweId={finding.data.cwe_id} owaspCategory={finding.data.owasp_category} />
          </header>
          <Card>
            <CardHeader>
              <CardTitle>Code context</CardTitle>
            </CardHeader>
            <CardContent>
              <CodeSnippet
                code={finding.data.code_snippet}
                path={finding.data.file_path}
                startLine={finding.data.snippet_start_line}
                flaggedStart={finding.data.line_start}
                flaggedEnd={finding.data.line_end}
              />
            </CardContent>
          </Card>
          <ExplanationPanel
            originalCode={finding.data.code_snippet}
            explanation={explanation.data}
            pending={request.isPending}
            failedToStart={request.isError}
            onRetry={retry}
          />
          <StatusControls findingId={finding.data.id} status={finding.data.status} />
        </>
      )}
    </main>
  )
}
