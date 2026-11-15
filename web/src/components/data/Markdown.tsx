import type { ReactNode } from 'react'

// The collector guide is trusted, fixed text from the Python package with a
// small Markdown subset: paragraphs, "1." lists, **bold**, `code` and
// [text](https://…) links. Render it as React elements (never as HTML); only
// https links are made clickable and they open in a new tab without referrer.

function inline(text: string): ReactNode[] {
  return text.split(/(\*\*[^*]+\*\*|`[^`]+`|\*[^*]+\*|\[[^\]]+\]\(https:\/\/[^)\s]+\))/g).map((part, index) => {
    const link = part.match(/^\[([^\]]+)\]\((https:\/\/[^)\s]+)\)$/)
    if (link)
      return (
        <a key={index} href={link[2]} target="_blank" rel="noopener noreferrer" className="underline underline-offset-2">
          {link[1]}
        </a>
      )
    if (part.startsWith('**') && part.endsWith('**')) return <strong key={index}>{part.slice(2, -2)}</strong>
    if (part.startsWith('`') && part.endsWith('`'))
      return (
        <code key={index} className="rounded-sm bg-muted px-1 font-mono text-[12px]">
          {part.slice(1, -1)}
        </code>
      )
    if (part.startsWith('*') && part.endsWith('*') && part.length > 2) return <em key={index}>{part.slice(1, -1)}</em>
    return part
  })
}

export function Markdown({ text }: { text: string }) {
  const blocks: ReactNode[] = []
  let list: string[] = []
  const flush = () => {
    if (list.length) {
      blocks.push(
        <ol key={`l${blocks.length}`} className="list-decimal space-y-1 pl-5">
          {list.map((item, index) => (
            <li key={index}>{inline(item)}</li>
          ))}
        </ol>,
      )
      list = []
    }
  }
  for (const line of text.split('\n')) {
    const item = line.match(/^\d+\.\s+(.*)$/)
    if (item) {
      list.push(item[1])
      continue
    }
    flush()
    if (line.trim()) blocks.push(<p key={`p${blocks.length}`}>{inline(line)}</p>)
  }
  flush()
  return <div className="max-w-[100ch] space-y-2 text-[13px]">{blocks}</div>
}
