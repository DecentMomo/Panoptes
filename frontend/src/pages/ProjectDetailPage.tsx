import { useState, type DragEvent } from "react"
import { Link, useParams } from "react-router-dom"
import { useQuery, useQueryClient } from "@tanstack/react-query"
import { toast } from "sonner"

import { ApiError } from "@/api/client"
import { uploadScan, listScans } from "@/api/scans"
import { Badge } from "@/components/ui/badge"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import type { Scan } from "@/types"

function isActive(status: string): boolean {
  return status === "queued" || status === "running"
}

export function ProjectDetailPage() {
  const { projectId } = useParams()
  const id = Number(projectId)
  const queryClient = useQueryClient()
  const [dragging, setDragging] = useState(false)
  const [uploading, setUploading] = useState(false)
  const scans = useQuery({
    queryKey: ["scans", id],
    queryFn: () => listScans(id),
    enabled: Number.isFinite(id),
    refetchInterval: (query) =>
      query.state.data?.some((scan) => isActive(scan.status)) ? 2000 : false,
  })

  async function upload(file: File) {
    if (!file.name.toLowerCase().endsWith(".zip")) {
      toast.error("Upload a .zip archive.")
      return
    }
    setUploading(true)
    try {
      await uploadScan(id, file)
      await queryClient.invalidateQueries({ queryKey: ["scans", id] })
      toast.success("Scan started")
    } catch (error) {
      const message = error instanceof ApiError ? error.message : "Could not start the scan."
      toast.error(message)
    } finally {
      setUploading(false)
    }
  }

  function onDrop(event: DragEvent) {
    event.preventDefault()
    setDragging(false)
    const file = event.dataTransfer.files[0]
    if (file) {
      void upload(file)
    }
  }

  return (
    <main className="mx-auto flex min-h-svh w-full max-w-5xl flex-col gap-6 p-6">
      <header className="flex items-center justify-between gap-4">
        <div>
          <p className="text-sm text-muted-foreground">
            <Link className="underline underline-offset-4" to="/">
              Projects
            </Link>
          </p>
          <h1 className="text-2xl font-medium">Upload a scan</h1>
        </div>
      </header>

      <Card>
        <CardHeader>
          <CardTitle>Source archive</CardTitle>
          <CardDescription>
            A .zip of source code. It is scanned statically and then deleted.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <label
            onDragOver={(event) => {
              event.preventDefault()
              setDragging(true)
            }}
            onDragLeave={() => setDragging(false)}
            onDrop={onDrop}
            className={`flex cursor-pointer flex-col items-center gap-2 rounded-lg border border-dashed px-6 py-10 text-sm ${
              dragging ? "border-foreground bg-muted" : "border-border"
            }`}
          >
            <span>{uploading ? "Uploading…" : "Drop a .zip here, or click to choose one"}</span>
            <input
              type="file"
              accept=".zip,application/zip"
              className="sr-only"
              disabled={uploading}
              onChange={(event) => {
                const file = event.target.files?.[0]
                if (file) {
                  void upload(file)
                }
                event.target.value = ""
              }}
            />
          </label>
        </CardContent>
      </Card>

      {scans.isPending ? (
        <p className="text-sm text-muted-foreground">Loading scans…</p>
      ) : scans.isError ? (
        <p className="text-sm text-destructive">Could not load scans.</p>
      ) : scans.data.length === 0 ? (
        <p className="text-sm text-muted-foreground">No scans yet.</p>
      ) : (
        <div className="flex flex-col gap-3">
          {scans.data.map((scan) => (
            <ScanRow key={scan.id} scan={scan} />
          ))}
        </div>
      )}
    </main>
  )
}

function ScanRow({ scan }: { scan: Scan }) {
  return (
    <Card>
      <CardContent className="flex items-center justify-between gap-3 py-4">
        <div>
          <Link className="font-medium underline underline-offset-4" to={`/scans/${scan.id}`}>
            {scan.source_name}
          </Link>
          {scan.error_message ? (
            <p className="text-sm text-destructive">{scan.error_message}</p>
          ) : null}
        </div>
        <Badge variant={scan.status === "failed" ? "destructive" : "secondary"}>{scan.status}</Badge>
      </CardContent>
    </Card>
  )
}
