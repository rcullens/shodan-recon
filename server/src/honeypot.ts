/**
 * Honeypot detection heuristics.
 *
 * 1. Hard exclude: Shodan tags honeypot, honeytrap, tarpit, censyshoneypot
 * 2. Hard exclude: known honeypot product/framework names
 * 3. Hard exclude: stock honeypot banner regexes
 * 4. Soft signal only: dense dangerous-port footprint
 */
import type { ShodanMatch } from './types.js';

const HARD_TAGS = new Set(['honeypot', 'honeytrap', 'tarpit', 'censyshoneypot']);

const HONEYPOT_PRODUCTS = [
  'cowrie', 'kippo', 'dionaea', 'conpot', 'glastopf', 'amun', 'honeyd',
  'snare', 'tanner', 'honeytrap', 'endlessh', 'rdpy', 'opencanary', 'honeybee',
];

const BANNER_PATTERNS: RegExp[] = [
  /cowrie/i, /kippo/i, /dionaea/i, /conpot/i, /glastopf/i, /honeyd/i, /opencanary/i,
  /this is a honeypot/i, /honeypot\.shodan\.io/i,
  /(?:^|\n)SSH-2\.0-OpenSSH_5\.1p1 Debian-5\s*$/i,
];

const DANGEROUS = new Set([21, 22, 23, 445, 1433, 3306, 3389, 5432, 5900, 6379, 27017]);

export interface HoneypotVerdict {
  isHoneypot: boolean;
  reasons: string[];
}

export function detectHoneypot(match: ShodanMatch, siblingPorts?: number[]): HoneypotVerdict {
  const reasons: string[] = [];
  const tags = (match.tags || []).map((t) => t.toLowerCase());
  const product = (match.product || '').toLowerCase();
  const banner = match.data || '';
  const info = `${match.info || ''} ${match.http?.title || ''} ${match.http?.server || ''}`;

  for (const t of tags) {
    if (HARD_TAGS.has(t)) reasons.push(`Shodan tag:${t}`);
  }
  for (const hp of HONEYPOT_PRODUCTS) {
    if (product.includes(hp) || banner.toLowerCase().includes(hp) || info.toLowerCase().includes(hp)) {
      reasons.push(`Known honeypot product/name: ${hp}`);
    }
  }
  for (const re of BANNER_PATTERNS) {
    if (re.test(banner) || re.test(info)) {
      reasons.push(`Suspicious banner pattern: ${re.source.slice(0, 40)}`);
      break;
    }
  }
  if (siblingPorts && siblingPorts.length >= 8) {
    const dangerous = siblingPorts.filter((p) => DANGEROUS.has(p));
    if (dangerous.length >= 5) {
      reasons.push(`Dense dangerous-port footprint (${dangerous.length} high-risk ports)`);
    }
  }

  const hard = reasons.some(
    (r) =>
      r.startsWith('Shodan tag:') ||
      r.startsWith('Known honeypot') ||
      r.startsWith('Suspicious banner'),
  );
  return { isHoneypot: hard, reasons };
}

export function filterHoneypots(matches: ShodanMatch[]): {
  clean: ShodanMatch[];
  removed: Array<{ match: ShodanMatch; reasons: string[] }>;
} {
  const byIp = new Map<string, number[]>();
  for (const m of matches) {
    const list = byIp.get(m.ip_str) || [];
    list.push(m.port);
    byIp.set(m.ip_str, list);
  }

  const clean: ShodanMatch[] = [];
  const removed: Array<{ match: ShodanMatch; reasons: string[] }> = [];

  for (const m of matches) {
    const verdict = detectHoneypot(m, byIp.get(m.ip_str));
    if (verdict.isHoneypot) removed.push({ match: m, reasons: verdict.reasons });
    else clean.push(m);
  }
  return { clean, removed };
}

export const HONEYPOT_DOCS = `
Honeypot filter heuristics:
1. Hard exclude: Shodan tags honeypot, honeytrap, tarpit, censyshoneypot
2. Known honeypot products: Cowrie, Kippo, Dionaea, Conpot, Glastopf, OpenCanary, Endlessh, …
3. Suspicious stock banners / explicit honeypot strings
4. Soft signal only: ≥5 dangerous ports among ≥8 open ports on one IP
`.trim();
