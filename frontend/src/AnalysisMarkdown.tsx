import Markdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import './analysis-markdown.css';

/** Render generated/imported text without trusting embedded HTML or loading remote images. */
export function AnalysisMarkdown({ text }: { text?: string }) {
 return <div className="generated-text analysis-markdown"><Markdown
  remarkPlugins={[remarkGfm]}
  skipHtml
  components={{
   h1: ({children}) => <h4>{children}</h4>,
   h2: ({children}) => <h4>{children}</h4>,
   h3: ({children}) => <h4>{children}</h4>,
   h4: ({children}) => <h5>{children}</h5>,
   h5: ({children}) => <h6>{children}</h6>,
   h6: ({children}) => <h6>{children}</h6>,
   a: ({href,children}) => href && /^https?:\/\//i.test(href)
    ? <a href={href} target="_blank" rel="noopener noreferrer">{children}</a>
    : <span>{children}</span>,
   img: ({alt}) => alt ? <span>{alt}</span> : null,
   table: ({children}) => <div className="markdown-table-scroll" role="region" aria-label="Tabla del análisis" tabIndex={0}><table>{children}</table></div>,
  }}
 >{text ?? ''}</Markdown></div>;
}
