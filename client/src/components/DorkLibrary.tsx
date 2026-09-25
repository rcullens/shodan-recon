import { useCallback, useEffect, useState } from 'react';
import { api, type DorkEntry, type QueryVariant } from '../lib/api';

interface Props {
  onRun: (v: QueryVariant) => void;
  onUseAsNl?: (text: string) => void;
}

export function DorkLibrary({ onRun, onUseAsNl }: Props) {
  const [q, setQ] = useState('');
  const [category, setCategory] = useState('');
  const [categories, setCategories] = useState<Array<{ name: string; count: number }>>([]);
  const [results, setResults] = useState<DorkEntry[]>([]);
  const [total, setTotal] = useState(0);
  const [libCount, setLibCount] = useState<number | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async (query: string, cat: string) => {
    setLoading(true);
    setError(null);
    try {
      const data = await api.dorks({
        q: query || undefined,
        category: cat || undefined,
        limit: 50,
      });
      setResults(data.results);
      setTotal(data.total);
      setCategories(data.categories);
      setLibCount(data.categories.reduce((s, c) => s + c.count, 0));
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to load dorks');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load('', '');
  }, [load]);

  useEffect(() => {
    const t = window.setTimeout(() => void load(q.trim(), category), 250);
    return () => window.clearTimeout(t);
  }, [q, category, load]);

  const runDork = (d: DorkEntry) => {
    onRun({
      label: `Library: ${d.title}`.slice(0, 60),
      query: d.query,
      kind: 'creative',
      rationale: `Dork library [${d.category}/${d.source}]${
        d.description ? ' — ' + d.description.slice(0, 80) : ''
      }`,
    });
  };

  return (
    <div className="dork-library">
      <div className="dork-search-row">
        <input
          className="dork-search"
          value={q}
          onChange={(e) => setQ(e.target.value)}
          placeholder="Search dork library…"
          spellCheck={false}
        />
      </div>
      <div className="dork-meta">
        {libCount != null ? `${total} match · ${libCount} in library` : 'Loading…'}
        {category ? ` · ${category}` : ''}
      </div>
      <div className="dork-cats">
        <button
          type="button"
          className={`dork-cat ${!category ? 'active' : ''}`}
          onClick={() => setCategory('')}
        >
          all
        </button>
        {categories.slice(0, 16).map((c) => (
          <button
            key={c.name}
            type="button"
            className={`dork-cat ${category === c.name ? 'active' : ''}`}
            onClick={() => setCategory(category === c.name ? '' : c.name)}
            title={`${c.count} dorks`}
          >
            {c.name}
            <span className="dork-cat-n">{c.count}</span>
          </button>
        ))}
      </div>
      {error && <div className="dork-error">{error}</div>}
      {loading && <div className="dork-loading">SCANNING LIBRARY…</div>}
      <div className="dork-list">
        {!loading && !results.length && (
          <div className="detail-empty">No dorks match. Try another keyword or category.</div>
        )}
        {results.map((d) => (
          <div key={d.id} className="dork-card">
            <div className="dork-card-top">
              <span className="dork-title">{d.title}</span>
              <span className="dork-cat-badge">{d.category}</span>
            </div>
            <div className="dork-query">{d.query}</div>
            {d.description ? <div className="dork-desc">{d.description}</div> : null}
            <div className="dork-actions">
              <button type="button" className="btn ghost" onClick={() => runDork(d)}>
                Run
              </button>
              {onUseAsNl && (
                <button
                  type="button"
                  className="btn ghost"
                  onClick={() => onUseAsNl(d.query)}
                  title="Paste into search box"
                >
                  Use
                </button>
              )}
              <span className="dork-src">{d.source}</span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
