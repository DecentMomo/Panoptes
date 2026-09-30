import { api } from "@/api/client"
import type { Explanation, Finding, StatusHistory } from "@/types"

export function getFinding(findingId: number): Promise<Finding> {
  return api<Finding>(`/findings/${findingId}`)
}

export function requestExplanation(findingId: number): Promise<Explanation> {
  return api<Explanation>(`/findings/${findingId}/explanation`, {
    method: "POST",
  })
}

export function getExplanation(findingId: number): Promise<Explanation> {
  return api<Explanation>(`/findings/${findingId}/explanation`)
}

export function updateStatus(
  findingId: number,
  body: { status: string; reason?: string },
): Promise<Finding> {
  return api<Finding>(`/findings/${findingId}/status`, {
    method: "PATCH",
    body: JSON.stringify(body),
  })
}

export function listHistory(findingId: number): Promise<StatusHistory[]> {
  return api<StatusHistory[]>(`/findings/${findingId}/history`)
}
