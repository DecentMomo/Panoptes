import { useEffect, useRef, useState } from "react"
import { Link, useParams } from "react-router-dom"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"

import {
  getExplanation,
  getFinding,
  requestExplanation,
} from "@/api/findings"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import type { ExplanationFailure } from "@/types"

const FAILURE_MESSAGES: Record<ExplanationFailure, string> = {
  model_unavailable: "The local Ollama model is unavailable.",
  timeout: "The local model took too long to respond.",
  invalid_response: "The local model returned an invalid response.",
}

export function FindingPage() {
  const { findingId } = useParams()
  const id = Number(findingId)
  const queryClient = useQueryClient()
  const started = useRef(false)
  const [requested, setRequested] = useState(false)

  const finding = useQuery({
    queryKey: ["finding", id],
    queryFn: () => getFinding(id),
    enabled: Number.isFinite(id),
  })
  const explanation = useQuery({
    queryKey: ["explanation", id],
    queryFn: () => getExplanation(id),
    enabled: requested,
    retry: false,
    refetchInterval: (query) => {
      const state = query.state.data?.status
      return state === "queued" || state === "running" ? 2000 : false
    },
  })
  const request = useMutation({
    mutationFn: () => requestExplanation(id),
    onSuccess: (data) => {
      queryClient.setQueryData(["explanation", id], data)
      setRequested(true)
    },
  })

  useEffect(() => {
    if (finding.data && !started.current) {
      started.current = true
      request.mutate()
    }
  }, [finding.data, request])

  function retry() {
    request.reset()
    request.mutate()
  }

  const ai = explanation.data
  const unavailable = request.isError || ai?.status === "failed"

  return (
    <main className="mx-auto flex min-h-svh w-full max-w-4xl flex-col gap-6 p-6">
      {finding.isPending ? (
        <p className="text-sm text-muted-foreground">Loading finding…</p>
      ) : finding.isError || !finding.data ? (
        <p className="text-sm text-destructive">Could not load this finding.</p>
      ) : (
        <>
          <header className="space-y-2">
            <Link
              className="text-sm underline underline-offset-4"
              to={`/scans/${finding.data.scan_id}`}
            >
              Back to scan
            </Link>
            <div className="flex flex-wrap items-center gap-2">
              <h1 className="text-2xl font-medium">{finding.data.title}</h1>
              <Badge variant="outline">{finding.data.severity}</Badge>
              <Badge variant="secondary">{finding.data.rule_id}</Badge>
            </div>
            <p className="text-sm text-muted-foreground">
              {finding.data.file_path}:{finding.data.line_start}
              {finding.data.cwe_id ? ` · ${finding.data.cwe_id}` : ""}
              {finding.data.owasp_category
                ? ` · ${finding.data.owasp_category}`
                : ""}
            </p>
          </header>

          <Card>
            <CardHeader>
              <CardTitle>Code context</CardTitle>
            </CardHeader>
            <CardContent>
              <pre className="overflow-x-auto rounded-md bg-muted p-4 text-sm">
                <code>{finding.data.code_snippet}</code>
              </pre>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <div className="flex flex-wrap items-center gap-2">
                <CardTitle>Explanation</CardTitle>
                <Badge variant="outline">
                  {ai?.ai_generated === false ? "Scanner guidance" : "AI-generated"}
                </Badge>
              </div>
              {ai?.ai_generated !== false ? (
                <p className="text-sm text-muted-foreground">
                  Review AI-generated suggestions before applying them.
                </p>
              ) : null}
            </CardHeader>
            <CardContent className="space-y-4">
              {request.isPending ||
              ai?.status === "queued" ||
              ai?.status === "running" ? (
                <p className="text-sm text-muted-foreground">
                  The local model is preparing an explanation…
                </p>
              ) : unavailable ? (
                <div className="space-y-3">
                  <div>
                    <p className="font-medium">AI explanation unavailable</p>
                    <p className="text-sm text-muted-foreground">
                      {ai?.failure_reason
                        ? FAILURE_MESSAGES[ai.failure_reason]
                        : "The explanation request could not be started."}
                    </p>
                  </div>
                  <Button
                    type="button"
                    variant="outline"
                    onClick={retry}
                    disabled={request.isPending}
                  >
                    Retry
                  </Button>
                </div>
              ) : ai?.status === "completed" ? (
                <>
                  <section>
                    <h2 className="font-medium">What this means</h2>
                    <p className="text-sm text-muted-foreground">
                      {ai.plain_explanation}
                    </p>
                  </section>
                  <section>
                    <h2 className="font-medium">Why it matters</h2>
                    <p className="text-sm text-muted-foreground">
                      {ai.why_it_matters}
                    </p>
                  </section>
                  <section>
                    <h2 className="font-medium">Suggested code</h2>
                    <pre className="overflow-x-auto rounded-md bg-muted p-4 text-sm">
                      <code>{ai.fixed_code}</code>
                    </pre>
                    <p className="mt-2 text-sm text-muted-foreground">
                      {ai.fix_rationale}
                    </p>
                  </section>
                </>
              ) : null}
            </CardContent>
          </Card>
        </>
      )}
    </main>
  )
}
