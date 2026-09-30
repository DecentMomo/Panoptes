import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import type { Explanation, ExplanationFailure } from "@/types"

import { FixDiff } from "./FixDiff"

const FAILURE_MESSAGES: Record<ExplanationFailure, string> = {
  model_unavailable: "The local Ollama model is unavailable.",
  timeout: "The local model took too long to respond.",
  invalid_response: "The local model returned an invalid response.",
}

export function ExplanationPanel({
  originalCode,
  explanation,
  pending,
  failedToStart,
  onRetry,
}: {
  originalCode: string
  explanation: Explanation | undefined
  pending: boolean
  failedToStart: boolean
  onRetry: () => void
}) {
  const waiting =
    pending || explanation?.status === "queued" || explanation?.status === "running"
  const unavailable = failedToStart || explanation?.status === "failed"
  const generated = explanation?.ai_generated !== false

  return (
    <Card>
      <CardHeader>
        <CardTitle>Explanation</CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        {explanation && generated ? (
          <p className="rounded-md border-2 border-amber-500 bg-amber-500/10 px-4 py-3 text-base font-semibold">
            AI-generated, requires review
          </p>
        ) : null}
        {explanation?.ai_generated === false ? (
          <p className="text-sm font-medium">Scanner guidance</p>
        ) : null}
        {waiting ? (
          <p className="text-sm text-muted-foreground">
            The local model is preparing an explanation…
          </p>
        ) : unavailable ? (
          <div className="space-y-3">
            <div>
              <p className="font-medium">AI explanation unavailable</p>
              <p className="text-sm text-muted-foreground">
                {explanation?.failure_reason
                  ? FAILURE_MESSAGES[explanation.failure_reason]
                  : "The explanation request could not be started."}
              </p>
            </div>
            <Button type="button" variant="outline" onClick={onRetry}>
              Retry
            </Button>
          </div>
        ) : explanation?.status === "completed" ? (
          <>
            <section>
              <h2 className="font-medium">What this means</h2>
              <p className="text-sm text-muted-foreground">{explanation.plain_explanation}</p>
            </section>
            <section>
              <h2 className="font-medium">Why it matters</h2>
              <p className="text-sm text-muted-foreground">{explanation.why_it_matters}</p>
            </section>
            <section>
              <h2 className="font-medium">Suggested fix</h2>
              <FixDiff original={originalCode} fixed={explanation.fixed_code ?? ""} />
              <p className="mt-2 text-sm text-muted-foreground">{explanation.fix_rationale}</p>
            </section>
          </>
        ) : null}
      </CardContent>
    </Card>
  )
}
