import { useState } from 'react';
import type { CveExplanation } from '../shared/cve-explain';

interface Props {
  explanations: CveExplanation[];
  /** When true, first two cards start expanded. */
  expandFirst?: number;
}

function impactLabels(exp: CveExplanation): string {
  const names: Record<string, string> = {
    remote_takeover: 'remote takeover',
    stolen_credentials: 'stolen credentials',
    data_leak: 'data leak',
    denial_of_service: 'denial of service',
    privilege_escalation: 'privilege escalation',
    man_in_the_middle: 'in-transit snooping',
    code_injection: 'untrusted code/input',
    unknown: 'unspecified',
  };
  return exp.impacts.map((i) => names[i] || i).join(' · ');
}

function sourceLabel(exp: CveExplanation): string {
  if (exp.source === 'curated') return 'curated plain-English write-up';
  if (exp.source === 'published_text') return 'paraphrase of Shodan / NVD text';
  return 'no verified description — not inventing details';
}

export function VulnExplainList({ explanations, expandFirst = 2 }: Props) {
  if (!explanations.length) return null;

  return (
    <div className="vuln-card-list">
      <p className="vuln-disclaimer">
        Shodan linked these CVE IDs to this host from service versions or banners. That is a recon
        clue, not proof of a break-in. Explanations are defensive only — no exploit steps.
      </p>
      {explanations.map((exp, i) => (
        <VulnCard key={exp.id} exp={exp} defaultOpen={i < expandFirst} />
      ))}
    </div>
  );
}

function VulnCard({ exp, defaultOpen }: { exp: CveExplanation; defaultOpen: boolean }) {
  const [open, setOpen] = useState(defaultOpen);

  return (
    <article className={`vuln-card ${open ? 'open' : ''}`}>
      <button
        type="button"
        className="vuln-card-head"
        onClick={() => setOpen((v) => !v)}
        aria-expanded={open}
      >
        <span className="vuln-card-ids">
          <span className="tag vuln">{exp.id}</span>
          <span className={`severity-badge sev-${exp.severity}`}>{exp.severity}</span>
          {exp.cvss != null && <span className="cvss-chip">CVSS {exp.cvss}</span>}
        </span>
        <span className="vuln-card-title">{exp.title}</span>
        <span className="vuln-card-chevron">{open ? '▾' : '▸'}</span>
      </button>
      {open && (
        <div className="vuln-card-body">
          <div className="vuln-block">
            <h4>What it is</h4>
            <p>{exp.whatItIs}</p>
          </div>
          <div className="vuln-block">
            <h4>What it means</h4>
            <p>{exp.whatItMeans}</p>
          </div>
          <div className="vuln-block">
            <h4>How it can affect this host</h4>
            <p>{exp.hostImpact}</p>
          </div>
          <div className="vuln-card-meta">
            <span>Impact themes · {impactLabels(exp)}</span>
            <span>Source · {sourceLabel(exp)}</span>
            <a href={exp.nvdUrl} target="_blank" rel="noreferrer">
              NVD record ↗
            </a>
          </div>
          {exp.sourceDescription && (
            <details className="vuln-source-desc">
              <summary>Published technical description</summary>
              <p>{exp.sourceDescription}</p>
            </details>
          )}
        </div>
      )}
    </article>
  );
}

export function VulnChipRow({
  ids,
  titles,
}: {
  ids: string[];
  titles?: Record<string, string>;
}) {
  if (!ids.length) return null;
  const shown = ids.slice(0, 5);
  const extra = ids.length - shown.length;
  return (
    <div className="tag-list vuln-chip-row">
      {shown.map((id) => (
        <span key={id} className="tag vuln" title={titles?.[id] || id}>
          {id}
          {titles?.[id] ? (
            <span className="vuln-chip-nick">
              {titles[id].split('—')[0].trim().slice(0, 42)}
            </span>
          ) : null}
        </span>
      ))}
      {extra > 0 && <span className="tag vuln">+{extra} more</span>}
    </div>
  );
}
