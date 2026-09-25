import { useEffect, useMemo, useState } from 'react';
import { api, type HostDetailResponse, type RankedHost } from '../lib/api';
import { VulnChipRow, VulnExplainList } from './VulnExplainList';
import {
  collectHostVulns,
  explainCve,
  explainVulns,
  type CveExplanation,
  type HostImpactContext,
} from '../shared/cve-explain';

interface Props {
  host: RankedHost | null;
  onClose?: () => void;
}

export function HostDetail({ host, onClose }: Props) {
  const [detail, setDetail] = useState<HostDetailResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [explanations, setExplanations] = useState<CveExplanation[]>([]);

  useEffect(() => {
    if (!host) {
      setDetail(null);
      return;
    }
    if (import.meta.env.DEV && host.ip === '203.0.113.10') {
      setDetail(null);
      setLoading(false);
      setError(null);
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

  const h = detail?.host;
  const dataArr = (h?.data as Array<Record<string, unknown>>) || [];
  const vulnInputs = useMemo(() => {
    const extra = [...(detail?.ranking?.vulns || []), ...(host?.vulns || [])];
    return collectHostVulns(h, extra);
  }, [h, detail?.ranking?.vulns, host?.vulns]);

  const impactCtx = useMemo<HostImpactContext>(
    () => ({
      product: (h?.product as string) || host?.product,
      ports: (Array.isArray(h?.ports) ? (h!.ports as number[]) : host?.ports) || [],
      org: (h?.org as string) || host?.org,
    }),
    [h, host?.product, host?.ports, host?.org],
  );

  useEffect(() => {
    if (!vulnInputs.length) {
      setExplanations([]);
      return;
    }
    const attached = detail?.vuln_explanations;
    if (attached?.length) {
      setExplanations(attached);
      return;
    }
    setExplanations(explainVulns(vulnInputs, impactCtx));
    const unknown = vulnInputs.filter((v) => !v.summary && explainCve(v).source === 'unknown');
    if (!unknown.length) return;
    let cancelled = false;
    void api
      .explainCves(vulnInputs, impactCtx)
      .then((list) => {
        if (!cancelled && list.length) setExplanations(list);
      })
      .catch(() => {
        /* keep local explanations */
      });
    return () => {
      cancelled = true;
    };
  }, [host?.ip, vulnInputs, impactCtx, detail?.vuln_explanations]);

  if (!host) {
    return (
      <div className="panel detail-panel">
        <div className="panel-header">HOST DETAIL</div>
        <div className="detail-empty">Select a host from the results list.</div>
      </div>
    );
  }

  const vulns = vulnInputs.map((v) => v.id);

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
            <h3>Vulns · plain English</h3>
            <VulnExplainList explanations={explanations.length ? explanations : explainVulns(vulnInputs, impactCtx)} />
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
                {!!svc.vulns && (
                  <VulnChipRow
                    ids={collectHostVulns({ vulns: svc.vulns }).map((v) => v.id)}
                    titles={Object.fromEntries(explanations.map((e) => [e.id, e.title]))}
                  />
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
