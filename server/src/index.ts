import cors from 'cors';
import dotenv from 'dotenv';
import express, { type Response } from 'express';
import rateLimit from 'express-rate-limit';
import path from 'path';
import { fileURLToPath } from 'url';
import { filterHoneypots, HONEYPOT_DOCS } from './honeypot.js';
import { translateNaturalLanguage } from './nl-translator.js';
import { getCategories, loadDorkLibrary, searchDorks } from './dork-library.js';
import { rankAndAggregate } from './ranking.js';
import { delay, getApiInfo, getHost, searchHosts, ShodanError } from './shodan.js';
import type { SearchResult, ShodanMatch } from './types.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
dotenv.config({ path: path.resolve(__dirname, '../../.env') });
dotenv.config({ path: path.resolve(__dirname, '../../.env.local'), override: true });

const app = express();
const PORT = Number(process.env.PORT) || 8787;

app.use(cors({ origin: true }));
app.use(express.json({ limit: '256kb' }));

app.use(
  '/api/',
  rateLimit({
    windowMs: 60_000,
    max: 30,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Local rate limit — max 30 requests/min to the proxy' },
  }),
);

app.get('/api/health', (_req, res) => {
  res.json({
    ok: true,
    hasKey: Boolean(process.env.SHODAN_API_KEY?.trim()),
    honeypot_docs: HONEYPOT_DOCS,
  });
});

app.get('/api/info', async (_req, res) => {
  try {
    const info = await getApiInfo();
    res.json({
      plan: info.plan,
      query_credits: info.query_credits,
      scan_credits: info.scan_credits,
      unlocked: info.unlocked,
    });
  } catch (e) {
    handleError(res, e);
  }
});

app.post('/api/translate', (req, res) => {
  const { query } = req.body as { query?: string };
  if (!query || typeof query !== 'string') {
    res.status(400).json({ error: 'Body must include { query: string }' });
    return;
  }
  res.json(translateNaturalLanguage(query));
});

app.post('/api/search', async (req, res) => {
  const { query, label, page } = req.body as {
    query?: string;
    label?: string;
    page?: number;
  };
  if (!query || typeof query !== 'string') {
    res.status(400).json({ error: 'Body must include { query: string }' });
    return;
  }

  try {
    const data = await searchHosts(query, page || 1);
    const { clean, removed } = filterHoneypots(data.matches);
    const ranked = rankAndAggregate(clean);

    let credits: number | null = null;
    try {
      const info = await getApiInfo();
      credits = info.query_credits ?? null;
    } catch {
      /* ignore */
    }

    const result: SearchResult = {
      query,
      query_label: label || 'search',
      total: data.total,
      filtered_honeypots: removed.length,
      matches: ranked,
      credits_left: credits,
    };
    res.json(result);
  } catch (e) {
    handleError(res, e);
  }
});

app.post('/api/recon', async (req, res) => {
  const { natural, runVariants = true, maxVariants = 3 } = req.body as {
    natural?: string;
    runVariants?: boolean;
    maxVariants?: number;
  };
  if (!natural || typeof natural !== 'string') {
    res.status(400).json({ error: 'Body must include { natural: string }' });
    return;
  }

  const translated = translateNaturalLanguage(natural);
  const toRun = [
    translated.standard,
    ...(runVariants ? translated.variants.slice(0, Math.min(6, maxVariants)) : []),
  ];

  const results: SearchResult[] = [];

  for (let i = 0; i < toRun.length; i++) {
    const v = toRun[i];
    if (!v.query) continue;
    try {
      if (i > 0) await delay(1100);
      const data = await searchHosts(v.query, 1);
      const { clean, removed } = filterHoneypots(data.matches);
      const ranked = rankAndAggregate(clean);
      results.push({
        query: v.query,
        query_label: v.label,
        total: data.total,
        filtered_honeypots: removed.length,
        matches: ranked,
      });
    } catch (e) {
      const msg = e instanceof ShodanError ? e.message : e instanceof Error ? e.message : 'Search failed';
      const status = e instanceof ShodanError ? e.status : 500;
      results.push({
        query: v.query,
        query_label: v.label,
        total: 0,
        filtered_honeypots: 0,
        matches: [],
        error: `${status}: ${msg}`,
      });
      if (e instanceof ShodanError && (e.status === 401 || e.status === 402)) break;
    }
  }

  let credits: number | null = null;
  try {
    const info = await getApiInfo();
    credits = info.query_credits ?? null;
  } catch {
    /* ignore */
  }

  const mergedMap = new Map<string, (typeof results)[0]['matches'][0]>();
  for (const r of results) {
    for (const h of r.matches) {
      const prev = mergedMap.get(h.ip);
      if (!prev || h.score > prev.score) mergedMap.set(h.ip, h);
    }
  }
  const merged = [...mergedMap.values()].sort((a, b) => b.score - a.score);

  res.json({
    translated,
    results,
    merged,
    credits_left: credits,
    honeypot_docs: HONEYPOT_DOCS,
  });
});


app.get('/api/dorks', (req, res) => {
  try {
    const q = typeof req.query.q === 'string' ? req.query.q : undefined;
    const category = typeof req.query.category === 'string' ? req.query.category : undefined;
    const source = typeof req.query.source === 'string' ? req.query.source : undefined;
    const limit = req.query.limit ? Number(req.query.limit) : 40;
    const offset = req.query.offset ? Number(req.query.offset) : 0;
    const result = searchDorks({ q, category, source, limit, offset });
    res.json(result);
  } catch (e) {
    handleError(res, e);
  }
});

app.get('/api/dorks/categories', (_req, res) => {
  try {
    const lib = loadDorkLibrary();
    res.json({ count: lib.count, categories: getCategories() });
  } catch (e) {
    handleError(res, e);
  }
});

app.get('/api/host/:ip', async (req, res) => {
  const ip = req.params.ip;
  if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(ip) && !/^[0-9a-fA-F:]+$/.test(ip)) {
    res.status(400).json({ error: 'Invalid IP' });
    return;
  }
  try {
    const host = await getHost(ip);
    const tags = ((host.tags as string[]) || []).map((t) => t.toLowerCase());
    const dataArr = (host.data as Array<Record<string, unknown>>) || [];

    const asMatches: ShodanMatch[] = (dataArr.length ? dataArr : [{}]).slice(0, 40).map((d) => ({
      ip_str: ip,
      port: Number(d.port) || 0,
      product: d.product as string | undefined,
      version: d.version as string | undefined,
      org: host.org as string | undefined,
      data: d.data as string | undefined,
      tags: host.tags as string[] | undefined,
      vulns: (host.vulns as string[] | Record<string, unknown>) || undefined,
      location: {
        city: host.city as string | undefined,
        region_code: host.region_code as string | undefined,
        country_code: host.country_code as string | undefined,
        country_name: host.country_name as string | undefined,
      },
      hostnames: (host.hostnames as string[]) || [],
      http: d.http as ShodanMatch['http'],
      ssl: d.ssl as ShodanMatch['ssl'],
      opts: d.opts as ShodanMatch['opts'],
      timestamp: (d.timestamp as string | undefined) || (host.last_update as string | undefined),
    }));

    const { clean, removed } = filterHoneypots(asMatches);
    const reasons = [...new Set(removed.flatMap((r) => r.reasons))];
    const ranked = rankAndAggregate(clean.length ? clean : asMatches);
    const hardHoney =
      tags.some((t) => ['honeypot', 'honeytrap', 'tarpit', 'censyshoneypot'].includes(t)) ||
      reasons.some(
        (r) =>
          r.startsWith('Shodan tag:') ||
          r.startsWith('Known honeypot') ||
          r.startsWith('Suspicious banner'),
      );

    res.json({
      host,
      honeypot: hardHoney,
      honeypot_reasons: reasons,
      ranking: ranked[0] || null,
    });
  } catch (e) {
    handleError(res, e);
  }
});

function handleError(res: Response, e: unknown) {
  if (e instanceof ShodanError) {
    res.status(e.status >= 400 && e.status < 600 ? e.status : 502).json({
      error: e.message,
      code: e.code,
    });
    return;
  }
  console.error('[server]', e instanceof Error ? e.message : e);
  res.status(500).json({ error: e instanceof Error ? e.message : 'Internal error' });
}

app.listen(PORT, () => {
  const hasKey = Boolean(process.env.SHODAN_API_KEY?.trim());
  console.log(`[shodan-recon] API proxy on http://localhost:${PORT}`);
  console.log(`[shodan-recon] SHODAN_API_KEY loaded: ${hasKey ? 'yes' : 'NO — set in .env'}`);
});
