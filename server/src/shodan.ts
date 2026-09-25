/**
 * Thin Shodan REST client. Key never leaves the server process.
 */
import type { ApiInfo, ShodanMatch } from './types.js';

const BASE = 'https://api.shodan.io';

export class ShodanError extends Error {
  constructor(
    message: string,
    public status: number,
    public code?: string,
  ) {
    super(message);
    this.name = 'ShodanError';
  }
}

function getKey(): string {
  const key = process.env.SHODAN_API_KEY?.trim();
  if (!key) {
    throw new ShodanError(
      'SHODAN_API_KEY not configured. Set it in /workspace/shodan-recon/.env',
      500,
      'NO_KEY',
    );
  }
  return key;
}

async function shodanFetch(path: string, params: Record<string, string> = {}): Promise<unknown> {
  const key = getKey();
  const url = new URL(path.startsWith('http') ? path : `${BASE}${path}`);
  url.searchParams.set('key', key);
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== '') url.searchParams.set(k, v);
  }

  const res = await fetch(url.toString(), {
    headers: { Accept: 'application/json' },
  });

  const text = await res.text();
  let body: unknown = null;
  try {
    body = text ? JSON.parse(text) : null;
  } catch {
    body = { error: text };
  }

  if (!res.ok) {
    const errMsg =
      (body as { error?: string })?.error ||
      (res.status === 401
        ? 'Invalid Shodan API key'
        : res.status === 402
          ? 'Shodan query credits exhausted (402)'
          : res.status === 429
            ? 'Shodan rate limit exceeded — slow down'
            : `Shodan API error ${res.status}`);
    throw new ShodanError(errMsg, res.status, res.status === 402 ? 'NO_CREDITS' : undefined);
  }

  return body;
}

export interface SearchResponse {
  matches: ShodanMatch[];
  total: number;
}

export async function searchHosts(query: string, page = 1): Promise<SearchResponse> {
  const data = (await shodanFetch('/shodan/host/search', {
    query,
    page: String(page),
  })) as SearchResponse;
  return {
    matches: data.matches || [],
    total: data.total ?? 0,
  };
}

export async function getHost(ip: string): Promise<Record<string, unknown>> {
  return (await shodanFetch(`/shodan/host/${encodeURIComponent(ip)}`)) as Record<string, unknown>;
}

export async function getApiInfo(): Promise<ApiInfo> {
  return (await shodanFetch('/api-info')) as ApiInfo;
}

export function delay(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}
