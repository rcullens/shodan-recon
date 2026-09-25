/**
 * Heuristic NL → Shodan query translator. No LLM required for v1.
 */
import type { QueryVariant, TranslateResult } from './types.js';
import { stripLocationFilters, suggestDorksForIntent } from './dork-library.js';

const US_STATES: Record<string, string> = {
  alabama: 'AL', alaska: 'AK', arizona: 'AZ', arkansas: 'AR', california: 'CA',
  colorado: 'CO', connecticut: 'CT', delaware: 'DE', florida: 'FL', georgia: 'GA',
  hawaii: 'HI', idaho: 'ID', illinois: 'IL', indiana: 'IN', iowa: 'IA',
  kansas: 'KS', kentucky: 'KY', louisiana: 'LA', maine: 'ME', maryland: 'MD',
  massachusetts: 'MA', michigan: 'MI', minnesota: 'MN', mississippi: 'MS',
  missouri: 'MO', montana: 'MT', nebraska: 'NE', nevada: 'NV', 'new hampshire': 'NH',
  'new jersey': 'NJ', 'new mexico': 'NM', 'new york': 'NY', 'north carolina': 'NC',
  'north dakota': 'ND', ohio: 'OH', oklahoma: 'OK', oregon: 'OR', pennsylvania: 'PA',
  'rhode island': 'RI', 'south carolina': 'SC', 'south dakota': 'SD', tennessee: 'TN',
  texas: 'TX', utah: 'UT', vermont: 'VT', virginia: 'VA', washington: 'WA',
  'west virginia': 'WV', wisconsin: 'WI', wyoming: 'WY',
};

const COUNTRIES: Record<string, string> = {
  'united states': 'US', usa: 'US', america: 'US', us: 'US',
  canada: 'CA', mexico: 'MX', 'united kingdom': 'GB', uk: 'GB', britain: 'GB',
  germany: 'DE', france: 'FR', spain: 'ES', italy: 'IT', brazil: 'BR',
  australia: 'AU', japan: 'JP', china: 'CN', india: 'IN', russia: 'RU',
  netherlands: 'NL', sweden: 'SE', poland: 'PL', israel: 'IL', singapore: 'SG',
};

interface DeviceProfile {
  keywords: string[];
  standard: string;
  variants: Array<{ label: string; query: string; rationale: string }>;
}

const DEVICES: DeviceProfile[] = [
  {
    keywords: ['webcam', 'webcams', 'ip camera', 'ip cameras', 'cctv', 'camera', 'cameras', 'surveillance'],
    standard: 'webcam',
    variants: [
      { label: 'RTSP cameras', query: 'port:554 has_screenshot:true', rationale: 'RTSP streams often expose live video' },
      { label: 'Hikvision', query: 'product:"Hikvision IP Camera"', rationale: 'Common commercial IP camera brand' },
      { label: 'Axis cameras', query: 'product:Axis', rationale: 'Axis Communications devices' },
      { label: 'HTTP camera titles', query: 'http.title:"Camera" OR http.title:"DVR" OR http.title:"NVR"', rationale: 'Web UI titles for camera/DVR gear' },
      { label: 'Screenshot + cam', query: 'has_screenshot:true "camera"', rationale: 'Devices Shodan snapped with camera banners' },
      { label: 'yawcam / webcamXP', query: '"Server: yawcam" OR "Server: webcamXP" OR "Server: IP Webcam"', rationale: 'Known webcam software banners' },
    ],
  },
  {
    keywords: ['router', 'routers', 'gateway', 'gateways'],
    standard: 'product:router OR "Router"',
    variants: [
      { label: 'Cisco IOS', query: 'product:"Cisco IOS"', rationale: 'Cisco router/switch OS banners' },
      { label: 'MikroTik', query: 'product:MikroTik OR http.title:"RouterOS"', rationale: 'MikroTik RouterOS devices' },
      { label: 'OpenWRT / DD-WRT', query: 'http.title:"OpenWrt" OR http.title:"DD-WRT"', rationale: 'Common open-source firmware' },
      { label: 'Admin login pages', query: 'http.title:"router" http.title:"login"', rationale: 'Router admin panels' },
      { label: 'SNMP routers', query: 'port:161 "router"', rationale: 'SNMP-exposed network gear' },
    ],
  },
  {
    keywords: ['printer', 'printers'],
    standard: 'product:printer OR port:9100',
    variants: [
      { label: 'HP JetDirect', query: 'product:"HP JetDirect" OR port:9100', rationale: 'Raw print protocol' },
      { label: 'IPP printers', query: 'port:631 product:CUPS OR "Internet Printing Protocol"', rationale: 'IPP/CUPS services' },
      { label: 'Printer web UI', query: 'http.title:"Printer" OR http.title:"LaserJet"', rationale: 'Embedded printer HTTP UIs' },
    ],
  },
  {
    keywords: ['scada', 'ics', 'plc', 'industrial', 'modbus'],
    standard: 'tag:ics OR port:502',
    variants: [
      { label: 'Modbus', query: 'port:502', rationale: 'Modbus TCP industrial protocol' },
      { label: 'BACnet', query: 'port:47808', rationale: 'Building automation protocol' },
      { label: 'Siemens S7', query: 'port:102 product:Siemens', rationale: 'Siemens S7 PLC' },
      { label: 'ICS tagged', query: 'tag:ics', rationale: 'Shodan ICS classification tag' },
    ],
  },
  {
    keywords: ['mongodb', 'mongo'],
    standard: 'product:MongoDB',
    variants: [
      { label: 'Open MongoDB', query: 'product:MongoDB -authentication', rationale: 'Often unauthenticated instances' },
      { label: 'Default Mongo port', query: 'port:27017 MongoDB', rationale: 'Standard MongoDB port' },
    ],
  },
  {
    keywords: ['elasticsearch', 'elastic'],
    standard: 'product:Elasticsearch',
    variants: [
      { label: 'Open Elastic', query: 'port:9200 "elasticsearch"', rationale: 'HTTP API on 9200' },
      { label: 'No auth elastic', query: 'product:Elasticsearch -authentication', rationale: 'Unauthenticated clusters' },
    ],
  },
  {
    keywords: ['rdp', 'remote desktop'],
    standard: 'port:3389',
    variants: [
      { label: 'RDP with screenshot', query: 'port:3389 has_screenshot:true', rationale: 'RDP desktops Shodan captured' },
      { label: 'Windows RDP', query: 'port:3389 os:"Windows"', rationale: 'Windows RDP endpoints' },
    ],
  },
  {
    keywords: ['ssh', 'ssh servers'],
    standard: 'port:22 product:OpenSSH',
    variants: [
      { label: 'Old OpenSSH', query: 'product:OpenSSH version:5 OR version:6', rationale: 'Outdated SSH versions' },
      { label: 'Dropbear', query: 'product:Dropbear', rationale: 'Embedded SSH (routers/IoT)' },
    ],
  },
  {
    keywords: ['ftp', 'ftp servers'],
    standard: 'port:21',
    variants: [
      { label: 'Anonymous FTP', query: 'port:21 "Anonymous user logged in"', rationale: 'Anon-login FTP banners' },
      { label: 'vsftpd / ProFTPD', query: 'product:vsftpd OR product:ProFTPD', rationale: 'Common FTP daemons' },
    ],
  },
  {
    keywords: ['nas', 'synology', 'qnap'],
    standard: 'product:Synology OR product:QNAP OR http.title:"NAS"',
    variants: [
      { label: 'Synology DSM', query: 'http.title:"Synology" OR product:Synology', rationale: 'Synology DiskStation' },
      { label: 'QNAP', query: 'product:QNAP OR http.title:"QNAP"', rationale: 'QNAP NAS devices' },
    ],
  },
  {
    keywords: ['vnc'],
    standard: 'port:5900',
    variants: [
      { label: 'VNC + screenshot', query: 'port:5900 has_screenshot:true', rationale: 'VNC with captured screen' },
      { label: 'Unauth VNC', query: 'port:5900 "RFB" "Authentication: None" OR "authentication disabled"', rationale: 'No-auth VNC' },
    ],
  },
  {
    keywords: ['database', 'databases', 'sql'],
    standard: 'port:3306 OR port:5432 OR port:1433',
    variants: [
      { label: 'MySQL', query: 'product:MySQL', rationale: 'MySQL servers' },
      { label: 'PostgreSQL', query: 'product:PostgreSQL', rationale: 'Postgres servers' },
      { label: 'MSSQL', query: 'port:1433 product:Microsoft', rationale: 'SQL Server' },
    ],
  },
];

function escapeShodan(s: string): string {
  return s.replace(/"/g, '\\"');
}

function extractLocation(text: string): { city?: string; state?: string; country?: string; rest: string } {
  let rest = text;
  let city: string | undefined;
  let state: string | undefined;
  let country: string | undefined;

  const inMatch =
    rest.match(/\bin\s+([a-zA-Z][a-zA-Z\s.'-]+?)(?:\s*$|,|\s+near|\s+with|\s+that)/i) ||
    rest.match(/\bin\s+(.+)$/i);

  if (inMatch) {
    let loc = inMatch[1].trim().replace(/[.?!,]+$/, '');
    rest = rest.replace(inMatch[0], ' ').trim();
    const locLower = loc.toLowerCase();

    for (const [name, code] of Object.entries(COUNTRIES)) {
      if (locLower === name || locLower.endsWith(' ' + name) || locLower.startsWith(name + ' ')) {
        country = code;
        loc = loc.replace(new RegExp(name, 'i'), '').trim();
        break;
      }
    }

    const stateMatch = loc.match(/^(.+?)[,\s]+([A-Za-z]{2}|[A-Za-z ]+)$/);
    if (stateMatch) {
      const maybeCity = stateMatch[1].trim();
      const maybeState = stateMatch[2].trim().toLowerCase();
      if (US_STATES[maybeState]) {
        state = US_STATES[maybeState];
        city = maybeCity;
        if (!country) country = 'US';
      } else if (maybeState.length === 2 && Object.values(US_STATES).includes(maybeState.toUpperCase())) {
        state = maybeState.toUpperCase();
        city = maybeCity;
        if (!country) country = 'US';
      } else if (COUNTRIES[maybeState]) {
        country = COUNTRIES[maybeState];
        city = maybeCity;
      } else {
        city = loc;
      }
    } else if (loc) {
      if (COUNTRIES[locLower]) country = COUNTRIES[locLower];
      else if (US_STATES[locLower]) {
        state = US_STATES[locLower];
        if (!country) country = 'US';
      } else city = loc;
    }
  }

  return { city, state, country, rest: rest.replace(/\s+/g, ' ').trim() };
}

function locationFilters(city?: string, state?: string, country?: string): string {
  const parts: string[] = [];
  if (city) parts.push(`city:"${escapeShodan(city)}"`);
  if (state) parts.push(`state:${state}`);
  if (country) parts.push(`country:${country}`);
  return parts.join(' ');
}

function findDevice(text: string): DeviceProfile | null {
  const lower = text.toLowerCase();
  let best: DeviceProfile | null = null;
  let bestLen = 0;
  for (const profile of DEVICES) {
    for (const kw of profile.keywords) {
      if (lower.includes(kw) && kw.length > bestLen) {
        best = profile;
        bestLen = kw.length;
      }
    }
  }
  return best;
}

function looksLikeShodan(q: string): boolean {
  return /\b(city|country|port|product|org|hostname|os|vuln|tag|has_screenshot|http\.title|ssl|net|asn|state):/i.test(q);
}

export function translateNaturalLanguage(input: string): TranslateResult {
  const original = input.trim();
  if (!original) {
    return {
      original,
      standard: { label: 'Empty', query: '', kind: 'standard', rationale: 'No query provided' },
      variants: [],
    };
  }

  if (looksLikeShodan(original)) {
    return {
      original,
      standard: {
        label: 'Direct Shodan syntax',
        query: original,
        kind: 'standard',
        rationale: 'Input already uses Shodan filters',
      },
      variants: [
        { label: 'With screenshots', query: `${original} has_screenshot:true`, kind: 'creative', rationale: 'Prefer hosts with screenshots' },
        { label: 'Exclude honeypots', query: `${original} -tag:honeypot`, kind: 'creative', rationale: 'Query-time honeypot exclusion' },
        { label: 'With vulns', query: `${original} has_vuln:true`, kind: 'creative', rationale: 'Only hosts with known CVEs' },
        ...suggestDorksForIntent(original, original, 3).map((d) => ({
          label: `Library: ${d.title}`.slice(0, 60),
          query: d.query,
          kind: 'creative' as const,
          rationale: `Dork library [${d.category}/${d.source}]`,
        })),
      ],
    };
  }

  const { city, state, country, rest } = extractLocation(original);
  const loc = locationFilters(city, state, country);
  const device = findDevice(rest || original);

  let core = '';
  if (device) core = device.standard;
  else {
    const cleaned = (rest || original)
      .replace(/\b(find|show|search|for|me|the|a|an|all|any|please|looking|get|list)\b/gi, ' ')
      .replace(/\s+/g, ' ')
      .trim();
    core = cleaned ? `"${escapeShodan(cleaned)}"` : '';
  }

  const standardQuery = [core, loc].filter(Boolean).join(' ').trim() || original;

  const standard: QueryVariant = {
    label: 'Standard',
    query: standardQuery,
    kind: 'standard',
    rationale: device
      ? `Device profile "${device.keywords[0]}" + location filters`
      : 'Free-text + extracted location filters',
  };

  const variants: QueryVariant[] = [];
  if (device) {
    for (const v of device.variants.slice(0, 6)) {
      variants.push({
        label: v.label,
        query: [v.query, loc].filter(Boolean).join(' ').trim(),
        kind: 'creative',
        rationale: v.rationale,
      });
    }
  } else {
    if (loc) {
      variants.push({
        label: 'Screenshots in area',
        query: `has_screenshot:true ${loc}`,
        kind: 'creative',
        rationale: 'Any snapshotted services in the location',
      });
    }
    variants.push({
      label: 'With known vulns',
      query: [core, 'has_vuln:true', loc].filter(Boolean).join(' '),
      kind: 'creative',
      rationale: 'Hosts Shodan associates with CVEs',
    });
  }

  if (!variants.some((v) => v.query.includes('-tag:honeypot'))) {
    variants.push({
      label: 'No honeypot tag',
      query: `${standardQuery} -tag:honeypot`,
      kind: 'creative',
      rationale: 'Same standard query minus honeypot-tagged hosts',
    });
  }

  // Enrich with community dork-library matches (creative / untested)
  const libraryHits = suggestDorksForIntent(original, standardQuery, 6);
  for (const d of libraryHits) {
    const core = stripLocationFilters(d.query);
    if (!core) continue;
    const q = [core, loc].filter(Boolean).join(' ').trim();
    variants.push({
      label: `Library: ${d.title}`.slice(0, 60),
      query: q,
      kind: 'creative',
      rationale: `Dork library [${d.category}/${d.source}]${d.description ? ' — ' + d.description.slice(0, 80) : ''}`,
    });
  }

  const seen = new Set<string>([standard.query]);
  const unique = variants.filter((v) => {
    if (seen.has(v.query)) return false;
    seen.add(v.query);
    return true;
  });

  // Prefer mix: keep device variants first, then library, cap at 8
  return { original, standard, variants: unique.slice(0, 8) };
}
