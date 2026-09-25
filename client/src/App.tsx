import { useCallback, useEffect, useState } from 'react';
import { DorkLibrary } from './components/DorkLibrary';
import { HostDetail } from './components/HostDetail';
import { HostList } from './components/HostList';
import { QueryList } from './components/QueryList';
import { SettingsModal } from './components/SettingsModal';
import {
  api,
  isNativeMode,
  type QueryVariant,
  type RankedHost,
  type SearchResult,
  type TranslateResult,
} from './lib/api';

function creditsClass(credits: number | null): string {
  if (credits == null) return 'warn';
  if (credits === 0) return 'err';
  if (credits <= 20) return 'warn';
  return 'ok';
}

function creditsLabel(credits: number | null, plan: string | null): string {
  if (credits == null) return 'credits —';
  const unit = credits === 1 ? 'query credit' : 'query credits';
  const planBit = plan ? ` · ${plan.toUpperCase()}` : '';
  return `${credits} ${unit}${planBit}`;
}

export default function App() {
  const [nl, setNl] = useState('webcams in Waco Texas');
  const [translated, setTranslated] = useState<TranslateResult | null>(null);
  const [selectedQuery, setSelectedQuery] = useState<string | null>(null);
  const [hosts, setHosts] = useState<RankedHost[]>([]);
  const [selectedHost, setSelectedHost] = useState<RankedHost | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [credits, setCredits] = useState<number | null>(null);
  const [plan, setPlan] = useState<string | null>(null);
  const [hasKey, setHasKey] = useState<boolean | null>(null);
  const [stats, setStats] = useState<{ total?: number; filtered?: number; label?: string }>({});
  const [variantResults, setVariantResults] = useState<SearchResult[]>([]);
  const [leftTab, setLeftTab] = useState<'variants' | 'dorks'>('variants');
  const [settingsOpen, setSettingsOpen] = useState(false);
  const native = isNativeMode();

  const refreshCredits = useCallback(async () => {
    try {
      const i = await api.info();
      setCredits(typeof i.query_credits === 'number' ? i.query_credits : null);
      setPlan(i.plan ?? null);
    } catch {
      setCredits(null);
    }
  }, []);

  useEffect(() => {
    api
      .health()
      .then((h) => setHasKey(h.hasKey))
      .catch(() => setHasKey(false));
    void refreshCredits();
    const id = window.setInterval(() => void refreshCredits(), 60_000);
    return () => window.clearInterval(id);
  }, [refreshCredits]);

  const runTranslate = useCallback(async (q: string) => {
    const t = await api.translate(q);
    setTranslated(t);
    setSelectedQuery(t.standard.query);
    setLeftTab('variants');
    return t;
  }, []);

  const runRecon = async () => {
    if (!nl.trim()) return;
    setLoading(true);
    setError(null);
    setSelectedHost(null);
    try {
      const t = await runTranslate(nl.trim());
      const data = await api.recon(nl.trim(), 3);
      setTranslated(data.translated || t);
      setHosts(data.merged);
      setVariantResults(data.results);
      if (data.credits_left != null) setCredits(data.credits_left);
      else void refreshCredits();
      const filtered = data.results.reduce((s, r) => s + (r.filtered_honeypots || 0), 0);
      const total = Math.max(0, ...data.results.map((r) => r.total));
      setStats({ total, filtered, label: 'merged variants' });
      const firstErr = data.results.find((r) => r.error);
      if (firstErr?.error && !data.merged.length) setError(firstErr.error);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Recon failed');
      setHosts([]);
    } finally {
      setLoading(false);
      void refreshCredits();
    }
  };

  const runOne = async (v: QueryVariant) => {
    setLoading(true);
    setError(null);
    setSelectedQuery(v.query);
    try {
      const r = await api.search(v.query, v.label);
      setHosts(r.matches);
      setStats({ total: r.total, filtered: r.filtered_honeypots, label: v.label });
      if (r.credits_left != null) setCredits(r.credits_left);
      if (r.error) setError(r.error);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Search failed');
    } finally {
      setLoading(false);
      void refreshCredits();
    }
  };

  const onKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      void runRecon();
    }
  };

  return (
    <div className="app-shell">
      <header className="topbar">
        <div className="brand">
          <h1>SHODAN RECON</h1>
          <span className="tag">// {native ? 'android · standalone' : 'local · desktop'} · authorized only</span>
        </div>
        <div className="status-pills">
          <span className={`pill mode-pill ${native ? 'ok' : ''}`}>
            {native ? 'NATIVE' : 'DESKTOP'}
          </span>
          <span className={`pill ${hasKey ? 'ok' : 'err'}`}>
            API KEY {hasKey ? 'LOADED' : 'MISSING'}
          </span>
          <button
            type="button"
            className="pill"
            onClick={() => setSettingsOpen(true)}
            title="Paste / manage Shodan API key"
          >
            SETTINGS
          </button>
          <button
            type="button"
            className={`pill credits-pill ${creditsClass(credits)}`}
            title={
              'Shodan query credits remaining on this API key. ' +
              'Each search / recon variant spends credits. ' +
              'Click to refresh from /api/info (also auto-refreshes every 60s).'
            }
            onClick={() => void refreshCredits()}
          >
            {creditsLabel(credits, plan)}
          </button>
        </div>
      </header>

      <section className="search-panel">
        <div className="search-row">
          <input
            className="search-input"
            value={nl}
            onChange={(e) => setNl(e.target.value)}
            onKeyDown={onKeyDown}
            placeholder='Natural English — e.g. "webcams in Waco Texas"'
            spellCheck={false}
          />
          <button className="btn" disabled={loading || !nl.trim()} onClick={() => void runRecon()}>
            {loading ? 'Scanning…' : 'Recon'}
          </button>
          <button
            className="btn magenta"
            disabled={loading || !nl.trim()}
            onClick={() => void runTranslate(nl.trim()).catch((e) => setError(String(e.message)))}
          >
            Translate only
          </button>
        </div>
        <div className="hints">
          Heuristic NL→Shodan + community dork library (no LLM required). Try{' '}
          <code>webcams in Waco Texas</code>, <code>ics modbus</code>, <code>port:3389 country:US</code>
        </div>
      </section>

      {error && <div className="error-banner">{error}</div>}

      <div className="main-grid">
        <aside className="panel left-panel">
          <div className="panel-header left-tabs">
            <button
              type="button"
              className={`tab ${leftTab === 'variants' ? 'active' : ''}`}
              onClick={() => setLeftTab('variants')}
            >
              Variants
              <span className="tab-n">{translated ? 1 + translated.variants.length : 0}</span>
            </button>
            <button
              type="button"
              className={`tab ${leftTab === 'dorks' ? 'active' : ''}`}
              onClick={() => setLeftTab('dorks')}
            >
              Dork library
            </button>
          </div>
          <div className="panel-body">
            {leftTab === 'variants' ? (
              <>
                <QueryList
                  standard={translated?.standard ?? null}
                  variants={translated?.variants ?? []}
                  selected={selectedQuery}
                  onSelect={(q) => setSelectedQuery(q.query)}
                  onRunOne={(q) => void runOne(q)}
                />
                {variantResults.length > 0 && (
                  <div className="run-breakdown">
                    <div className="run-breakdown-h">LAST RUN BREAKDOWN</div>
                    {variantResults.map((r) => (
                      <div key={r.query_label + r.query} className="run-breakdown-row">
                        {r.query_label}:{' '}
                        {r.error
                          ? `ERR ${r.error}`
                          : `${r.matches.length} hosts (total ${r.total}, −${r.filtered_honeypots} hp)`}
                      </div>
                    ))}
                  </div>
                )}
              </>
            ) : (
              <DorkLibrary
                onRun={(v) => void runOne(v)}
                onUseAsNl={(text) => {
                  setNl(text);
                  setLeftTab('variants');
                }}
              />
            )}
          </div>
        </aside>

        <section className="panel">
          <div className="panel-header">Results</div>
          <HostList
            hosts={hosts}
            selectedIp={selectedHost?.ip ?? null}
            onSelect={setSelectedHost}
            loading={loading}
            stats={stats}
          />
        </section>

        <HostDetail host={selectedHost} onClose={() => setSelectedHost(null)} />
      </div>

      <footer className="footer-note">
        METADATA VIEW ONLY · No device login, exploits, or stream hijacking · Searching ≠ authorization ·
        Unauthorized access is illegal
      </footer>

      <SettingsModal
        open={settingsOpen}
        onClose={() => setSettingsOpen(false)}
        onSaved={() => {
          void api.health().then((h) => setHasKey(h.hasKey)).catch(() => setHasKey(false));
          void refreshCredits();
        }}
      />
    </div>
  );
}
