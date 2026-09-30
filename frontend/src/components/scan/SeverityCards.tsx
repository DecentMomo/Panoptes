import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"

const SEVERITIES = ["critical", "high", "medium", "low", "info"]

export function SeverityCards({ counts }: { counts: Record<string, number> }) {
  return (
    <div className="grid gap-3 sm:grid-cols-5">
      {SEVERITIES.map((severity) => (
        <Card key={severity}>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm capitalize text-muted-foreground">{severity}</CardTitle>
          </CardHeader>
          <CardContent className="text-2xl font-medium">{counts[severity] ?? 0}</CardContent>
        </Card>
      ))}
    </div>
  )
}
