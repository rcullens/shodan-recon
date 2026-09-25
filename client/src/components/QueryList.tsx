import type { QueryVariant } from '../lib/api';

interface Props {
  standard: QueryVariant | null;
  variants: QueryVariant[];
  selected: string | null;
  onSelect: (q: QueryVariant) => void;
  onRunOne: (q: QueryVariant) => void;
}

export function QueryList({ standard, variants, selected, onSelect, onRunOne }: Props) {
  const all = standard ? [standard, ...variants] : variants;

  if (!all.length) {
    return (
      <div className="detail-empty">
        Enter a natural-language query to generate Shodan syntax variants.
      </div>
    );
  }

  return (
    <>
      {all.map((v) => (
        <div
          key={v.query + v.label}
          className={`query-card ${v.kind} ${selected === v.query ? 'selected' : ''}`}
          onClick={() => onSelect(v)}
        >
          <div className="label">
            {v.kind === 'standard' ? '◉ STANDARD' : '◇ CREATIVE / UNTESTED'} — {v.label}
          </div>
          <div className="q">{v.query}</div>
          <div className="why">{v.rationale}</div>
          <div style={{ marginTop: '0.45rem' }}>
            <button
              className="btn ghost"
              onClick={(e) => {
                e.stopPropagation();
                onRunOne(v);
              }}
            >
              Run this query
            </button>
          </div>
        </div>
      ))}
    </>
  );
}
