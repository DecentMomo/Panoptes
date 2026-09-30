import { diffLines } from "diff"

export function FixDiff({ original, fixed }: { original: string; fixed: string }) {
  const parts = diffLines(original, fixed)
  return (
    <pre className="overflow-x-auto rounded-md bg-muted p-4 text-sm">
      {parts.map((part, index) => (
        <span
          key={`${part.added ? "add" : part.removed ? "remove" : "same"}-${index}`}
          className={
            part.added
              ? "block bg-emerald-500/15"
              : part.removed
                ? "block bg-rose-500/15"
                : "block"
          }
        >
          {part.added ? "+ " : part.removed ? "- " : "  "}
          {part.value}
        </span>
      ))}
    </pre>
  )
}
