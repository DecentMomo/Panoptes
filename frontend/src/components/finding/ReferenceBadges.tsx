import { Badge } from "@/components/ui/badge"

function cweUrl(cweId: string): string | null {
  const number = cweId.match(/\d+/)?.[0]
  return number ? `https://cwe.mitre.org/data/definitions/${number}.html` : null
}

function owaspUrl(label: string): string | null {
  const slug = label.replace(":2025 - ", "_2025-").replaceAll(" ", "_")
  return slug.startsWith("A") ? `https://owasp.org/Top10/2025/${slug}/` : null
}

export function ReferenceBadges({
  cweId,
  owaspCategory,
}: {
  cweId: string | null
  owaspCategory: string | null
}) {
  const cwe = cweId ? cweUrl(cweId) : null
  const owasp = owaspCategory ? owaspUrl(owaspCategory) : null
  return (
    <div className="flex flex-wrap gap-2">
      {cwe && cweId ? (
        <a href={cwe} target="_blank" rel="noreferrer">
          <Badge variant="outline">{cweId}</Badge>
        </a>
      ) : null}
      {owasp && owaspCategory ? (
        <a href={owasp} target="_blank" rel="noreferrer">
          <Badge variant="secondary">{owaspCategory}</Badge>
        </a>
      ) : null}
    </div>
  )
}
