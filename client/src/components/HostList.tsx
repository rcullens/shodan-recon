import type { RankedHost } from '../lib/api';
import { explainCve } from '../shared/cve-explain';
import { VulnChipRow } from './VulnExplainList';

interface Props {
  hosts: RankedHost[];
  selectedIp: string | null;
  onSelect: (h: RankedHost) => void;
  loading?: boolean;
  stats?: { total?: number; filtered?: number; label?: string };
}

function scoreClass(score: number) {
  if (score >= 60) return 'score-high';
  if (score >= 35) return 'score-mid';
  return 'score-low';
}

export function HostList({ hosts, selectedIp, onSelect, loading, stats }: Props) {
  return (
    <>
      <div className="stats-bar">
        <span>
          HOSTS <strong>{hosts.length}</strong>
        </span>
        {stats?.total != null && (
          <span>
            SHODAN TOTAL <strong>{stats.total}</strong>
          </span>
        )}
        {stats?.filtered != null && stats.filtered > 0 && (
          <span>
            HONEYPOTS FILTERED <strong>{stats.filtered}</strong>
          </span>
        )}
        {stats?.label && <span>QUERY · {stats.label}</span>}
      </div>
      <div className="panel-body">
        {loading && <div className="loading">SCANNING</div>}
        {!loading && !hosts.length && (
          <div className="detail-empty">No hosts yet. Run a recon search.</div>
        )}
        <div className="host-list">
          {hosts.map((h) => (
            <div
              key={h.ip}
              className={`host-item ${selectedIp === h.ip ? 'selected' : ''}`}
              onClick={() => onSelect(h)}
            >
              <div className="row1">
                <a
                  className="ip"
                  href={`https://www.shodan.io/host/${h.ip}`}
                  target="_blank"
                  rel="noreferrer"
                  onClick={(e) => e.stopPropagation()}
                  title="Open on shodan.io"
                >
                  {h.ip}
                </a>
                <span className={`score-badge ${scoreClass(h.score)}`}>{h.score}</span>
              </div>
              <div className="host-meta">
                {h.location && (
                  <span>
                    <strong>LOC</strong> {h.location}
                  </span>
                )}
                {h.org && (
                  <span>
                    <strong>ORG</strong> {h.org}
                  </span>
                )}
                {h.product && (
                  <span>
                    <strong>PROD</strong> {h.product}
                  </span>
                )}
              </div>
              <div className="ports">
                {h.ports.slice(0, 12).map((p) => (
                  <span key={p} className="port-chip">
                    {p}
                  </span>
                ))}
                {h.ports.length > 12 && (
                  <span className="port-chip">+{h.ports.length - 12}</span>
                )}
              </div>
              {h.score_reasons.length > 0 && (
                <div className="reasons">{h.score_reasons.slice(0, 3).join(' · ')}</div>
              )}
              {h.vulns.length > 0 && (
                <VulnChipRow
                  ids={h.vulns}
                  titles={Object.fromEntries(
                    h.vulns.map((id) => {
                      const e = explainCve(id);
                      return [id, e.source === 'curated' ? e.title : ''];
                    }),
                  )}
                />
              )}
              {h.banner_snippet && <div className="banner-snip">{h.banner_snippet}</div>}
            </div>
          ))}
        </div>
      </div>
    </>
  );
}
