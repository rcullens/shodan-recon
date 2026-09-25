import { Capacitor } from '@capacitor/core';
import { nativeApi } from './nativeApi';

export interface QueryVariant {
  label: string;
  query: string;
  kind: 'standard' | 'creative';
  rationale: string;
}

export interface TranslateResult {
  original: string;
  standard: QueryVariant;
  variants: QueryVariant[];
}

export interface RankedHost {
  ip: string;
  ports: number[];
  product?: string;
  org?: string;
  location?: string;
  country?: string;
  city?: string;
  hostnames: string[];
  tags: string[];
  vulns: string[];
  banner_snippet: string;
  score: number;
  score_reasons: string[];
  timestamp?: string;
  has_screenshot: boolean;
}

export interface SearchResult {
  query: string;
  query_label: string;
  total: number;
  filtered_honeypots: number;
  matches: RankedHost[];
  credits_left?: number | null;
  error?: string;
}

export interface ReconResponse {
  translated: TranslateResult;
  results: SearchResult[];
  merged: RankedHost[];
  credits_left: number | null;
  honeypot_docs: string;
}

export interface HostDetailResponse {
  host: Record<string, unknown>;
  honeypot: boolean;
  honeypot_reasons: string[];
  ranking: RankedHost | null;
}

export interface DorkEntry {
  id: string;
  source: string;
  category: string;
  title: string;
  query: string;
  description: string;
  tags: string[];
}

export interface DorkSearchResponse {
  total: number;
  results: DorkEntry[];
  categories: Array<{ name: string; count: number }>;
}

export interface ApiInfo {
  plan?: string;
  query_credits?: number;
  scan_credits?: number;
  unlocked?: boolean;
}

export function isNativeMode(): boolean {
  return Capacitor.isNativePlatform();
}

async function req<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, {
    ...init,
    headers: {
      'Content-Type': 'application/json',
      ...(init?.headers || {}),
    },
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw new Error((data as { error?: string }).error || `HTTP ${res.status}`);
  }
  return data as T;
}

const webApi = {
  health: () => req<{ ok: boolean; hasKey: boolean }>('/api/health'),
  info: () => req<ApiInfo>('/api/info'),
  translate: (query: string) =>
    req<TranslateResult>('/api/translate', {
      method: 'POST',
      body: JSON.stringify({ query }),
    }),
  recon: (natural: string, maxVariants = 3) =>
    req<ReconResponse>('/api/recon', {
      method: 'POST',
      body: JSON.stringify({ natural, runVariants: true, maxVariants }),
    }),
  search: (query: string, label?: string) =>
    req<SearchResult>('/api/search', {
      method: 'POST',
      body: JSON.stringify({ query, label }),
    }),
  host: (ip: string) => req<HostDetailResponse>(`/api/host/${encodeURIComponent(ip)}`),
  dorks: (params: { q?: string; category?: string; limit?: number; offset?: number } = {}) => {
    const sp = new URLSearchParams();
    if (params.q) sp.set('q', params.q);
    if (params.category) sp.set('category', params.category);
    if (params.limit != null) sp.set('limit', String(params.limit));
    if (params.offset != null) sp.set('offset', String(params.offset));
    const qs = sp.toString();
    return req<DorkSearchResponse>(`/api/dorks${qs ? `?${qs}` : ''}`);
  },
  dorkCategories: () =>
    req<{ count: number; categories: Array<{ name: string; count: number }> }>(
      '/api/dorks/categories',
    ),
};

/** Unified API: Express proxy on desktop/web, CapacitorHttp + shared modules on native. */
export const api = {
  health: () => (isNativeMode() ? nativeApi.health() : webApi.health()),
  info: () => (isNativeMode() ? nativeApi.info() : webApi.info()),
  translate: (query: string) =>
    isNativeMode() ? nativeApi.translate(query) : webApi.translate(query),
  recon: (natural: string, maxVariants = 3) =>
    isNativeMode() ? nativeApi.recon(natural, maxVariants) : webApi.recon(natural, maxVariants),
  search: (query: string, label?: string) =>
    isNativeMode() ? nativeApi.search(query, label) : webApi.search(query, label),
  host: (ip: string) => (isNativeMode() ? nativeApi.host(ip) : webApi.host(ip)),
  dorks: (params: { q?: string; category?: string; limit?: number; offset?: number } = {}) =>
    isNativeMode() ? nativeApi.dorks(params) : webApi.dorks(params),
  dorkCategories: () =>
    isNativeMode() ? nativeApi.dorkCategories() : webApi.dorkCategories(),
};
