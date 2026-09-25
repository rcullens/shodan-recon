/**
 * Standalone / Capacitor path: call api.shodan.io via CapacitorHttp (bypasses CORS),
 * run NL translate / honeypot / ranking / dorks in-browser from shared modules.
 */
import { CapacitorHttp } from '@capacitor/core';
import { filterHoneypots, HONEYPOT_DOCS } from '../shared/honeypot';
import { translateNaturalLanguage } from '../shared/nl-translator';
import { getCategories, loadDorkLibrary, searchDorks } from '../shared/dork-library';
import { rankAndAggregate } from '../shared/ranking';
import type { RankedHost, SearchResult, ShodanMatch, TranslateResult } from '../shared/types';
import {
  collectHostVulns,
  enrichUnknownVulns,
  explainVulns,
  hintFromCveDbBody,
  type CveExplanation,
  type HostImpactContext,
  type VulnInput,
} from '../shared/cve-explain';
import type {
  ApiInfo,
  DorkSearchResponse,
  HostDetailResponse,
  ReconResponse,
} from './api';
import { getApiKey } from './keyStore';

const BASE = 'https://api.shodan.io';

class ShodanError extends Error {
  constructor(
    message: string,
    public status: number,
    public code?: string,
  ) {
    super(message);
    this.name = 'ShodanError';
  }
}

async function shodanFetch(path: string, params: Record<string, string> = {}): Promise<unknown> {
  const key = await getApiKey();
  if (!key) {
    throw new ShodanError(
      'Shodan API key not set. Open Settings and paste your key from account.shodan.io',
      401,
      'NO_KEY',
    );
  }
  const url = new URL(path.startsWith('http') ? path : `${BASE}${path}`);
  url.searchParams.set('key', key);
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== '') url.searchParams.set(k, v);
  }

  const res = await CapacitorHttp.get({
    url: url.toString(),
    headers: { Accept: 'application/json' },
  });

  const status = res.status;
  let body: unknown = res.data;
  if (typeof body === 'string') {
    try {
      body = body ? JSON.parse(body) : null;
    } catch {
      body = { error: body };
    }
  }

  if (status < 200 || status >= 300) {
    const errMsg =
      (body as { error?: string })?.error ||
      (status === 401
        ? 'Invalid Shodan API key'
        : status === 402
          ? 'Shodan query credits exhausted (402)'
          : status === 429
            ? 'Shodan rate limit exceeded — slow down'
            : `Shodan API error ${status}`);
    throw new ShodanError(errMsg, status, status === 402 ? 'NO_CREDITS' : undefined);
  }
  return body;
}

function delay(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

async function fetchCveDbHint(id: string): Promise<{ summary?: string; cvss?: number } | null> {
  const url = `https://cvedb.shodan.io/cve/${encodeURIComponent(id)}`;
  try {
    const res = await CapacitorHttp.get({
      url,
      headers: { Accept: 'application/json' },
      connectTimeout: 4000,
      readTimeout: 4000,
    });
    if (res.status < 200 || res.status >= 300) return null;
    let body: unknown = res.data;
    if (typeof body === 'string') {
      try {
        body = body ? JSON.parse(body) : null;
      } catch {
        return null;
      }
    }
    return hintFromCveDbBody(body);
  } catch {
    return null;
  }
}

async function searchHosts(query: string, page = 1): Promise<{ matches: ShodanMatch[]; total: number }> {
  const data = (await shodanFetch('/shodan/host/search', {
    query,
    page: String(page),
  })) as { matches?: ShodanMatch[]; total?: number };
  return { matches: data.matches || [], total: data.total ?? 0 };
}

async function runSearch(query: string, label: string): Promise<SearchResult> {
  const data = await searchHosts(query, 1);
  const { clean, removed } = filterHoneypots(data.matches);
  const ranked = rankAndAggregate(clean);
  let credits: number | null = null;
  try {
    const info = (await shodanFetch('/api-info')) as ApiInfo;
    credits = typeof info.query_credits === 'number' ? info.query_credits : null;
  } catch {
    /* ignore */
  }
  return {
    query,
    query_label: label,
    total: data.total,
    filtered_honeypots: removed.length,
    matches: ranked,
    credits_left: credits,
  };
}

export const nativeApi = {
  health: async () => ({
    ok: true,
    hasKey: Boolean(await getApiKey()),
    honeypot_docs: HONEYPOT_DOCS,
  }),

  info: async (): Promise<ApiInfo> => {
    const info = (await shodanFetch('/api-info')) as ApiInfo;
    return {
      plan: info.plan,
      query_credits: info.query_credits,
      scan_credits: info.scan_credits,
      unlocked: info.unlocked,
    };
  },

  translate: async (query: string): Promise<TranslateResult> => translateNaturalLanguage(query),

  recon: async (natural: string, maxVariants = 3): Promise<ReconResponse> => {
    const translated = translateNaturalLanguage(natural);
    const toRun = [
      translated.standard,
      ...translated.variants.slice(0, Math.min(6, maxVariants)),
    ];
    const results: SearchResult[] = [];
    for (let i = 0; i < toRun.length; i++) {
      const v = toRun[i];
      if (!v.query) continue;
      try {
        if (i > 0) await delay(1100);
        results.push(await runSearch(v.query, v.label));
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
      const info = (await shodanFetch('/api-info')) as ApiInfo;
      credits = typeof info.query_credits === 'number' ? info.query_credits : null;
    } catch {
      /* ignore */
    }
    const mergedMap = new Map<string, RankedHost>();
    for (const r of results) {
      for (const h of r.matches) {
        const prev = mergedMap.get(h.ip);
        if (!prev || h.score > prev.score) mergedMap.set(h.ip, h);
      }
    }
    const merged = [...mergedMap.values()].sort((a, b) => b.score - a.score);
    return {
      translated,
      results,
      merged,
      credits_left: credits,
      honeypot_docs: HONEYPOT_DOCS,
    };
  },

  search: async (query: string, label?: string): Promise<SearchResult> => {
    try {
      return await runSearch(query, label || 'search');
    } catch (e) {
      if (e instanceof ShodanError) {
        return {
          query,
          query_label: label || 'search',
          total: 0,
          filtered_honeypots: 0,
          matches: [],
          error: e.message,
        };
      }
      throw e;
    }
  },

  host: async (ip: string): Promise<HostDetailResponse> => {
    const host = (await shodanFetch(`/shodan/host/${encodeURIComponent(ip)}`)) as Record<
      string,
      unknown
    >;
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
    const vulnInputs = await enrichUnknownVulns(
      collectHostVulns(host, ranked[0]?.vulns || []),
      fetchCveDbHint,
    );
    const vuln_explanations = explainVulns(vulnInputs, {
      product: (asMatches[0]?.product as string) || undefined,
      ports: ranked[0]?.ports,
      org: (host.org as string) || undefined,
    });
    const hardHoney =
      tags.some((t) => ['honeypot', 'honeytrap', 'tarpit', 'censyshoneypot'].includes(t)) ||
      reasons.some(
        (r) =>
          r.startsWith('Shodan tag:') ||
          r.startsWith('Known honeypot') ||
          r.startsWith('Suspicious banner'),
      );
    return {
      host,
      honeypot: hardHoney,
      honeypot_reasons: reasons,
      ranking: ranked[0] || null,
      vuln_explanations,
    };
  },

  explainCves: async (
    vulns: VulnInput[],
    context?: HostImpactContext,
  ): Promise<CveExplanation[]> => {
    const enriched = await enrichUnknownVulns(vulns, fetchCveDbHint);
    return explainVulns(enriched, context);
  },

  dorks: async (params: {
    q?: string;
    category?: string;
    limit?: number;
    offset?: number;
  } = {}): Promise<DorkSearchResponse> => {
    const result = searchDorks(params);
    return {
      total: result.total,
      results: result.results,
      categories: result.categories,
    };
  },

  dorkCategories: async () => {
    const lib = loadDorkLibrary();
    return { count: lib.count, categories: getCategories() };
  },
};
