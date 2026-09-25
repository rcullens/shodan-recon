/**
 * Searchable Shodan dork library ingested from community sources.
 * Used by NL translator for creative variants + /api/dorks browse UI.
 */
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

export interface DorkEntry {
  id: string;
  source: string;
  category: string;
  title: string;
  query: string;
  description: string;
  tags: string[];
  keywords?: string[];
}

export interface DorkLibrary {
  version: number;
  count: number;
  categories: Record<string, number>;
  dorks: DorkEntry[];
}

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DATA_PATH = path.resolve(__dirname, '../data/dorks.json');

let cached: DorkLibrary | null = null;

export function loadDorkLibrary(): DorkLibrary {
  if (cached) return cached;
  const raw = fs.readFileSync(DATA_PATH, 'utf8');
  cached = JSON.parse(raw) as DorkLibrary;
  return cached;
}

export function getCategories(): Array<{ name: string; count: number }> {
  const lib = loadDorkLibrary();
  return Object.entries(lib.categories)
    .map(([name, count]) => ({ name, count }))
    .sort((a, b) => b.count - a.count || a.name.localeCompare(b.name));
}

export interface DorkSearchOpts {
  q?: string;
  category?: string;
  source?: string;
  limit?: number;
  offset?: number;
}

export function searchDorks(opts: DorkSearchOpts = {}): {
  total: number;
  results: DorkEntry[];
  categories: Array<{ name: string; count: number }>;
} {
  const lib = loadDorkLibrary();
  const q = (opts.q || '').trim().toLowerCase();
  const tokens = q ? q.split(/\s+/).filter(Boolean) : [];
  const category = opts.category?.toLowerCase();
  const source = opts.source?.toLowerCase();
  const limit = Math.min(Math.max(opts.limit ?? 40, 1), 200);
  const offset = Math.max(opts.offset ?? 0, 0);

  let results = lib.dorks.filter((d) => {
    if (category && d.category !== category) return false;
    if (source && d.source !== source) return false;
    if (!tokens.length) return true;
    const hay = `${d.title} ${d.query} ${d.description} ${d.category} ${(d.tags || []).join(' ')} ${(d.keywords || []).join(' ')}`.toLowerCase();
    return tokens.every((t) => hay.includes(t));
  });

  // Simple relevance: prefer title/query matches
  if (tokens.length) {
    results = results
      .map((d) => {
        const title = d.title.toLowerCase();
        const query = d.query.toLowerCase();
        let score = 0;
        for (const t of tokens) {
          if (title.includes(t)) score += 3;
          if (query.includes(t)) score += 2;
          if (d.category.includes(t)) score += 1;
        }
        return { d, score };
      })
      .sort((a, b) => b.score - a.score || a.d.title.localeCompare(b.d.title))
      .map((x) => x.d);
  }

  const total = results.length;
  return {
    total,
    results: results.slice(offset, offset + limit),
    categories: getCategories(),
  };
}

/**
 * Given a natural-language intent / standard Shodan query, pick related library
 * dorks as creative / untested variants (location filters appended by caller).
 */
export function suggestDorksForIntent(
  natural: string,
  standardQuery: string,
  limit = 6,
): DorkEntry[] {
  const lib = loadDorkLibrary();
  const text = `${natural} ${standardQuery}`.toLowerCase();

  // Intent → preferred categories / keywords
  const intentMap: Array<{ test: RegExp; categories: string[]; boost: string[] }> = [
    { test: /webcam|camera|cctv|surveillance|dvr|nvr|ipcam/i, categories: ['webcams'], boost: ['webcam', 'camera', 'screenshot', 'hikvision', 'axis'] },
    { test: /scada|ics|plc|modbus|industrial|rtu|bacnet|dnp3/i, categories: ['ics-scada'], boost: ['scada', 'modbus', 'plc', 'siemens', 'abb'] },
    { test: /router|gateway|firewall|cisco|mikrotik/i, categories: ['network', 'routers', 'cisco'], boost: ['router', 'cisco', 'gateway'] },
    { test: /mongo|mysql|postgres|elastic|redis|database|sql/i, categories: ['databases'], boost: ['mongodb', 'mysql', 'elasticsearch', 'redis'] },
    { test: /rdp|vnc|ssh|telnet|remote desktop/i, categories: ['remote-access'], boost: ['rdp', 'vnc', 'ssh', '3389', '5900'] },
    { test: /printer|cups|jetdirect/i, categories: ['printers'], boost: ['printer', 'cups', 'jetdirect'] },
    { test: /nas|synology|qnap/i, categories: ['nas'], boost: ['synology', 'qnap', 'nas'] },
    { test: /voip|asterisk|pbx|sip/i, categories: ['voip'], boost: ['voip', 'asterisk', 'sip'] },
    { test: /ftp|anonymous/i, categories: ['ftp'], boost: ['ftp', 'anonymous'] },
    { test: /jenkins|gitlab|jira|admin|panel|dashboard/i, categories: ['administration', 'web-servers'], boost: ['jenkins', 'admin', 'login'] },
  ];

  let preferredCats = new Set<string>();
  let boostWords = new Set<string>();
  for (const m of intentMap) {
    if (m.test.test(text)) {
      m.categories.forEach((c) => preferredCats.add(c));
      m.boost.forEach((b) => boostWords.add(b));
    }
  }

  // Always extract free tokens from NL (drop stopwords)
  const stop = new Set([
    'the', 'and', 'for', 'with', 'that', 'this', 'from', 'into', 'find', 'show',
    'search', 'in', 'on', 'of', 'a', 'an', 'all', 'any', 'please', 'looking', 'get', 'list',
    'devices', 'device', 'servers', 'server', 'open', 'exposed',
  ]);
  const tokens = text
    .replace(/[^a-z0-9:\s"]+/gi, ' ')
    .split(/\s+/)
    .map((t) => t.toLowerCase())
    .filter((t) => t.length >= 3 && !stop.has(t));

  const scored = lib.dorks.map((d) => {
    let score = 0;
    if (preferredCats.has(d.category)) score += 8;
    const hay = `${d.title} ${d.query} ${d.description} ${(d.keywords || []).join(' ')}`.toLowerCase();
    for (const t of tokens) {
      if (hay.includes(t)) score += 2;
    }
    for (const b of boostWords) {
      if (hay.includes(b)) score += 3;
    }
    // Penalize exact duplicate of standard query
    if (d.query === standardQuery) score = -100;
    return { d, score };
  });

  scored.sort((a, b) => b.score - a.score);
  const out: DorkEntry[] = [];
  const seen = new Set<string>([standardQuery]);
  for (const { d, score } of scored) {
    if (score < 4) break;
    if (seen.has(d.query)) continue;
    seen.add(d.query);
    out.push(d);
    if (out.length >= limit) break;
  }
  return out;
}

/** Strip location filters from a library dork before re-appending caller location. */
export function stripLocationFilters(query: string): string {
  return query
    .replace(/\b(city|country|state|geo)\s*:\s*("[^"]*"|[^\s]+)/gi, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}
