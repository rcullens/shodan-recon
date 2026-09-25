import { useEffect, useState } from 'react';
import { api, type HostDetailResponse, type RankedHost } from '../lib/api';

interface Props {
  host: RankedHost | null;
  onClose?: () => void;
}

export function HostDetail({ host, onClose }: Props) {
  const [detail, setDetail] = useState<HostDetailResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!host) {
      setDetail(null);
      return;
    }
    let cancelled = false;
    setLoading(true);
    setError(null);
    api
      .host(host.ip)
      .then((d) => {
        if (!cancelled) setDetail(d);
      })
      .catch((e: Error) => {
        if (!cancelled) setError(e.message);
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [host?.ip]);

  if (!host) {
    return (
      <div className="panel detail-panel">
        <div className="panel-header">HOST DETAIL</div>
        <div className="detail-empty">Select a host from the results list.</div>
      </div>
    );
  }

  const h = detail?.host;
  const dataArr = (h?.data as Array<Record<string, unknown>>) || [];
  const vulns =
    detail?.ranking?.vulns ||
    (Array.isArray(h?.vulns) ? (h!.vulns as string[]) : h?.vulns ? Object.keys(h.vulns as object) : []) ||
    host.vulns;

  return (
    <div className="panel detail-panel open-mobile">
      <div className="panel-header">
        <span>HOST DETAIL</span>
        {onClose && (
          <button className="btn ghost" onClick={onClose}>
            CLOSE
          </button>
        )}
      </div>
      <div className="detail-body">
        <div className="detail-ip">{host.ip}</div>
        <div style={{ marginTop: '0.5rem', display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
          <a
            href={`https://www.shodan.io/host/${host.ip}`}
            target="_blank"
            rel="noreferrer"
            className="btn ghost"
          >
            Open shodan.io ↗
          </a>
          <span className={`score-badge ${host.score >= 60 ? 'score-high' : host.score >= 35 ? 'score-mid' : 'score-low'}`}>
            SCORE {detail?.ranking?.score ?? host.score}
          </span>
        </div>

        {loading && <div className="loading">FETCHING HOST</div>}
        {error && <div className="error-banner" style={{ margin: '0.75rem 0' }}>{error}</div>}
        {detail?.honeypot && (
          <div className="error-banner" style={{ margin: '0.75rem 0' }}>
            Honeypot signals: {detail.honeypot_reasons.join('; ')}
          </div>
        )}

        <div className="detail-section">
          <h3>Overview</h3>
          <div className="kv">
            <div className="k">Location</div>
            <div className="v">{host.location || '—'}</div>
            <div className="k">Org</div>
            <div className="v">{(h?.org as string) || host.org || '—'}</div>
            <div className="k">ISP</div>
            <div className="v">{(h?.isp as string) || '—'}</div>
            <div className="k">ASN</div>
            <div className="v">{(h?.asn as string) || '—'}</div>
            <div className="k">OS</div>
            <div className="v">{(h?.os as string) || '—'}</div>
            <div className="k">Hostnames</div>
            <div className="v">
              {(host.hostnames.length ? host.hostnames : (h?.hostnames as string[]) || []).join(', ') ||
                '—'}
            </div>
            <div className="k">Ports</div>
            <div className="v">
              {(Array.isArray(h?.ports) ? (h!.ports as number[]) : host.ports).join(', ')}
            </div>
            <div className="k">Last update</div>
            <div className="v">{(h?.last_update as string) || host.timestamp || '—'}</div>
          </div>
        </div>

        {(detail?.ranking?.score_reasons || host.score_reasons).length > 0 && (
          <div className="detail-section">
            <h3>Rank reasons</h3>
            <div className="reasons">
              {(detail?.ranking?.score_reasons || host.score_reasons).join(' · ')}
            </div>
          </div>
        )}

        {vulns && vulns.length > 0 && (
          <div className="detail-section">
            <h3>Vulns</h3>
            <div className="tag-list">
              {vulns.map((v) => (
                <span key={v} className="tag vuln">
                  {v}
                </span>
              ))}
            </div>
          </div>
        )}

        {((h?.tags as string[]) || host.tags || []).length > 0 && (
          <div className="detail-section">
            <h3>Tags</h3>
            <div className="tag-list">
              {((h?.tags as string[]) || host.tags).map((t) => (
                <span key={t} className="tag">
                  {t}
                </span>
              ))}
            </div>
          </div>
        )}

        {dataArr.length > 0 && (
          <div className="detail-section">
            <h3>Services / Banners</h3>
            {dataArr.map((svc, i) => (
              <div key={i} style={{ marginBottom: '0.85rem' }}>
                <div className="host-meta" style={{ marginBottom: '0.35rem' }}>
                  <span>
                    <strong>PORT</strong> {String(svc.port)}/{String(svc.transport || 'tcp')}
                  </span>
                  {!!svc.product && (
                    <span>
                      <strong>PROD</strong> {String(svc.product)}
                      {svc.version ? ` ${String(svc.version)}` : ''}
                    </span>
                  )}
                </div>
                {!!(svc.http as { title?: string })?.title && (
                  <div className="host-meta">
                    <span>
                      <strong>HTTP TITLE</strong> {(svc.http as { title?: string }).title}
                    </span>
                  </div>
                )}
                <div className="banner-block">{String(svc.data || '(no banner)')}</div>
              </div>
            ))}
          </div>
        )}

        {!loading && !dataArr.length && host.banner_snippet && (
          <div className="detail-section">
            <h3>Banner snippet</h3>
            <div className="banner-block">{host.banner_snippet}</div>
          </div>
        )}
      </div>
    </div>
  );
}
