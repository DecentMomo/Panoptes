import { api } from "@/api/client"
import type { Stats } from "@/types"

export function getStats(): Promise<Stats> {
  return api<Stats>("/stats")
}
