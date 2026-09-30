import { PrismLight as SyntaxHighlighter } from "react-syntax-highlighter"
import javascript from "react-syntax-highlighter/dist/esm/languages/prism/javascript"
import python from "react-syntax-highlighter/dist/esm/languages/prism/python"
import { oneDark } from "react-syntax-highlighter/dist/esm/styles/prism"

SyntaxHighlighter.registerLanguage("python", python)
SyntaxHighlighter.registerLanguage("javascript", javascript)

function languageFor(path: string): "python" | "javascript" {
  return /\.(jsx?|tsx?|mjs|cjs)$/.test(path) ? "javascript" : "python"
}

export function CodeSnippet({
  code,
  path,
  startLine,
  flaggedStart,
  flaggedEnd,
}: {
  code: string
  path: string
  startLine: number
  flaggedStart: number
  flaggedEnd: number
}) {
  return (
    <SyntaxHighlighter
      language={languageFor(path)}
      style={oneDark}
      showLineNumbers
      startingLineNumber={startLine}
      wrapLongLines
      lineProps={(lineNumber) => ({
        style:
          lineNumber >= flaggedStart && lineNumber <= flaggedEnd
            ? { backgroundColor: "rgba(225, 29, 72, 0.25)", display: "block" }
            : { display: "block" },
      })}
    >
      {code || " "}
    </SyntaxHighlighter>
  )
}
