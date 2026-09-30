export const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const

// Red for critical and high, amber for medium, yellow for low, grey for info.
// Chosen against the dark background, which is what the app ships with.
const TEXT: Record<string, string> = {
  critical: "text-red-400 font-semibold",
  high: "text-red-400",
  medium: "text-amber-400",
  low: "text-yellow-300",
  info: "text-zinc-400",
}

const BORDER: Record<string, string> = {
  critical: "border-red-400/60",
  high: "border-red-400/60",
  medium: "border-amber-400/60",
  low: "border-yellow-300/60",
  info: "border-zinc-400/60",
}

export function severityText(severity: string): string {
  return TEXT[severity] ?? TEXT.info
}

export function severityBorder(severity: string): string {
  return BORDER[severity] ?? BORDER.info
}
