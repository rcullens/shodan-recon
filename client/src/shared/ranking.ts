/**
 * Rank hosts by estimated interestingness / vulnerability signal (0–100 heuristic).
 */
import type { RankedHost, ShodanMatch } from './types';

const DANGEROUS_PORTS: Record<number, { pts: number; reason: string }> = {
  21: { pts: 12, reason: 'FTP (21) often weak/anon' },
  23: { pts: 18, reason: 'Telnet (23) cleartext' },
  445: { pts: 16, reason: 'SMB (445)' },
  1433: { pts: 14, reason: 'MSSQL (1433)' },
  3306: { pts: 14, reason: 'MySQL (3306)' },
  3389: { pts: 15, reason: 'RDP (3389)' },
  5432: { pts: 14, reason: 'PostgreSQL (5432)' },
  5900: { pts: 16, reason: 'VNC (5900)' },
  6379: { pts: 15, reason: 'Redis (6379)' },
  27017: { pts: 16, reason: 'MongoDB (27017)' },
  9200: { pts: 14, reason: 'Elasticsearch (9200)' },
  11211: { pts: 12, reason: 'Memcached (11211)' },
  2375: { pts: 20, reason: 'Docker API unencrypted (2375)' },
  5555: { pts: 10, reason: 'ADB (5555)' },
  8291: { pts: 10, reason: 'Winbox (8291)' },
};

const OUTDATED: Array<{ re: RegExp; pts: number; reason: string }> = [
  { re: /OpenSSH[_ ]([1-6])\./i, pts: 12, reason: 'Outdated OpenSSH major version' },
  { re: /Apache\/([12]\.|2\.[0-2]\.)/i, pts: 10, reason: 'Outdated Apache' },
  { re: /nginx\/1\.[0-9]\./i, pts: 6, reason: 'Possibly old nginx 1.x' },
  { re: /PHP\/[45]\./i, pts: 12, reason: 'EOL PHP 4/5' },
  { re: /Microsoft-IIS\/[1-6]\./i, pts: 10, reason: 'Old IIS' },
  { re: /openssl\/0\./i, pts: 14, reason: 'Ancient OpenSSL 0.x' },
];

const NO_AUTH: RegExp[] = [
  /authentication:\s*disabled/i,
  /auth\s*disabled/i,
  /no\s*authentication/i,
  /anonymous\s*(?:user\s*)?logged\s*in/i,
  /login:\s*anonymous/i,
  /without\s*password/i,
  /"auth"\s*:\s*false/i,
];

function vulnList(match: ShodanMatch): string[] {
  if (!match.vulns) return [];
  if (Array.isArray(match.vulns)) return match.vulns.map(String);
  return Object.keys(match.vulns);
}

function scoreMatch(match: ShodanMatch, allPorts: number[]): { score: number; reasons: string[] } {
  let score = 10;
  const reasons: string[] = [];

  const vulns = vulnList(match);
  if (vulns.length) {
    score += Math.min(40, vulns.length * 10);
    reasons.push(
      `${vulns.length} known vuln(s): ${vulns.slice(0, 3).join(', ')}${vulns.length > 3 ? '…' : ''}`,
    );
  }

  for (const p of allPorts) {
    const d = DANGEROUS_PORTS[p];
    if (d) {
      score += d.pts;
      reasons.push(d.reason);
    }
  }

  const banner = `${match.data || ''}\n${match.info || ''}\n${match.http?.title || ''}`;
  for (const { re, pts, reason } of OUTDATED) {
    if (re.test(banner) || (match.version && re.test(`${match.product} ${match.version}`))) {
      score += pts;
      reasons.push(reason);
    }
  }

  for (const re of NO_AUTH) {
    if (re.test(banner)) {
      score += 18;
      reasons.push('No/weak auth hint in banner');
      break;
    }
  }

  if (match.tags?.includes('self-signed')) {
    score += 4;
    reasons.push('Self-signed TLS');
  }
  if (match.ssl?.cert?.expired) {
    score += 8;
    reasons.push('Expired TLS certificate');
  }

  const prod = (match.product || '').toLowerCase();
  if (/camera|webcam|hikvision|dahua|axis/i.test(prod) || /camera|webcam/i.test(banner)) {
    score += 8;
    reasons.push('Camera/IoT product exposure');
  }

  if (match.opts?.screenshot || (match.tags || []).includes('screenshot')) {
    score += 5;
    reasons.push('Has screenshot');
  }

  return { score: Math.min(100, score), reasons: [...new Set(reasons)].slice(0, 6) };
}

function locationString(m: ShodanMatch): string {
  const loc = m.location;
  if (!loc) return '';
  return [loc.city, loc.region_code, loc.country_code].filter(Boolean).join(', ');
}

export function rankAndAggregate(matches: ShodanMatch[]): RankedHost[] {
  const byIp = new Map<string, ShodanMatch[]>();
  for (const m of matches) {
    const list = byIp.get(m.ip_str) || [];
    list.push(m);
    byIp.set(m.ip_str, list);
  }

  const hosts: RankedHost[] = [];
  for (const [ip, group] of byIp) {
    const ports = [...new Set(group.map((g) => g.port))].sort((a, b) => a - b);
    let best = group[0];
    let bestVuln = vulnList(best).length;
    for (const g of group) {
      const vc = vulnList(g).length;
      if (vc > bestVuln || (g.data && (!best.data || g.data.length > best.data.length))) {
        best = g;
        bestVuln = vc;
      }
    }

    const { score, reasons } = scoreMatch(best, ports);
    hosts.push({
      ip,
      ports,
      product: best.product,
      org: best.org,
      location: locationString(best),
      country: best.location?.country_code,
      city: best.location?.city,
      hostnames: [...new Set(group.flatMap((g) => g.hostnames || []))],
      tags: [...new Set(group.flatMap((g) => g.tags || []))],
      vulns: [...new Set(group.flatMap(vulnList))],
      banner_snippet: (best.data || '').slice(0, 240).replace(/\n/g, '↵'),
      score,
      score_reasons: reasons,
      timestamp: best.timestamp,
      has_screenshot: group.some(
        (g) => !!(g.opts?.screenshot) || (g.tags || []).includes('screenshot'),
      ),
    });
  }

  hosts.sort((a, b) => b.score - a.score || a.ip.localeCompare(b.ip));
  return hosts;
}
