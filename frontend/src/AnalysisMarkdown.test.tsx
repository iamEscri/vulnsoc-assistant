import { describe, it, expect } from 'vitest';
import { renderToStaticMarkup } from 'react-dom/server';
import { AnalysisMarkdown } from './AnalysisMarkdown';

describe('AI Markdown presentation', () => {
 it('renders headings, emphasis, lists, tables and literal code', () => {
  const html = renderToStaticMarkup(<AnalysisMarkdown text={'### Impacto\n\n- **Producto:** Log4j\n\n| Factor | Puntos |\n| --- | --- |\n| KEV | 60 |\n\n```yaml\ntitle: Detection\n```'}/>);
  expect(html).toContain('<h4>Impacto</h4>');
  expect(html).toContain('<strong>Producto:</strong>');
  expect(html).toContain('<ul>');
  expect(html).toContain('<table>');
  expect(html).toContain('<td>60</td>');
  expect(html).toContain('title: Detection');
  expect(html).not.toContain('### Impacto');
 });
 it('blocks raw HTML, unsafe links and remote image requests', () => {
  const html = renderToStaticMarkup(<AnalysisMarkdown text={'<script>alert(1)</script>\n\n<img src=x onerror=alert(1)>\n\n[Bad](javascript:alert%281%29)\n\n![External](https://example.com/tracker.png)\n\n[Source](https://example.com/advisory)'}/>);
  expect(html).not.toMatch(/<script|<img|onerror|javascript:|tracker\.png/);
  expect(html).toContain('href="https://example.com/advisory"');
  expect(html).toContain('rel="noopener noreferrer"');
 });
});
