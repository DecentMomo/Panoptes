import { useQuery } from "@tanstack/react-query"

import { Badge } from "@/components/ui/badge"
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"

type HealthResponse = {
  status: string
}

async function fetchHealth(): Promise<HealthResponse> {
  const response = await fetch("/api/health")
  if (!response.ok) {
    throw new Error(`Backend responded with ${response.status}`)
  }
  return response.json() as Promise<HealthResponse>
}

export default function App() {
  const health = useQuery({ queryKey: ["health"], queryFn: fetchHealth })

  let status = <Badge variant="secondary">Checking…</Badge>
  if (health.isError) {
    status = <Badge variant="destructive">Unreachable</Badge>
  } else if (health.data) {
    status = <Badge>{health.data.status}</Badge>
  }

  return (
    <main className="flex min-h-svh items-center justify-center p-6">
      <Card className="w-full max-w-md">
        <CardHeader>
          <CardTitle className="text-2xl">Panoptes</CardTitle>
          <CardDescription>
            Many eyes on your code. Scanning arrives in a later phase — this
            page only checks that the API is reachable.
          </CardDescription>
        </CardHeader>
        <CardContent className="flex items-center justify-between">
          <span className="text-sm text-muted-foreground">Backend</span>
          {status}
        </CardContent>
      </Card>
    </main>
  )
}
