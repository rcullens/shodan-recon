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

export interface ShodanMatch {
  ip_str: string;
  port: number;
  transport?: string;
  product?: string;
  version?: string;
  org?: string;
  isp?: string;
  asn?: string;
  hostnames?: string[];
  domains?: string[];
  location?: {
    city?: string;
    region_code?: string;
    country_code?: string;
    country_name?: string;
    latitude?: number;
    longitude?: number;
  };
  data?: string;
  tags?: string[];
  vulns?: string[] | Record<string, unknown>;
  timestamp?: string;
  os?: string;
  info?: string;
  http?: {
    title?: string;
    server?: string;
    status?: number;
  };
  ssl?: {
    cert?: { subject?: { CN?: string }; expired?: boolean };
  };
  opts?: { screenshot?: { data?: string } };
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
  raw?: ShodanMatch;
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

export interface ApiInfo {
  query_credits?: number;
  scan_credits?: number;
  plan?: string;
  unlocked?: boolean;
}
