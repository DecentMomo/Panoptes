import { api } from "@/api/client"
import type { Explanation, Finding } from "@/types"

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
