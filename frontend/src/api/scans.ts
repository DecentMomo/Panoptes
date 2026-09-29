import { api } from "@/api/client"
import type { Finding, Scan, ScanDetail } from "@/types"

export function listScans(projectId: number): Promise<Scan[]> {
  return api<Scan[]>(`/projects/${projectId}/scans`)
}

export function uploadScan(projectId: number, file: File): Promise<Scan> {
  const body = new FormData()
  body.append("file", file)
  return api<Scan>(`/projects/${projectId}/scans`, { method: "POST", body })
}

export function cloneScan(projectId: number, url: string): Promise<Scan> {
  return api<Scan>(`/projects/${projectId}/scans/git`, {
    method: "POST",
    body: JSON.stringify({ url }),
  })
}

export function getScan(scanId: number): Promise<ScanDetail> {
  return api<ScanDetail>(`/scans/${scanId}`)
}

export function listFindings(scanId: number): Promise<Finding[]> {
  return api<Finding[]>(`/scans/${scanId}/findings`)
}
