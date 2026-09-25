import { useEffect, useState } from 'react';
import { getApiKey, setApiKey } from '../lib/keyStore';
import { isNativeMode } from '../lib/api';

interface Props {
  open: boolean;
  onClose: () => void;
  onSaved: () => void;
}

export function SettingsModal({ open, onClose, onSaved }: Props) {
  const [key, setKey] = useState('');
  const [saving, setSaving] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);

  useEffect(() => {
    if (!open) return;
    setMsg(null);
    void getApiKey().then(setKey);
  }, [open]);

  if (!open) return null;

  const save = async () => {
    setSaving(true);
    setMsg(null);
    try {
      await setApiKey(key);
      setMsg(key.trim() ? 'Key saved on device.' : 'Key cleared.');
      onSaved();
    } catch (e) {
      setMsg(e instanceof Error ? e.message : 'Save failed');
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="modal-backdrop" role="dialog" aria-modal="true" onClick={onClose}>
      <div className="modal-card" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <h2>SETTINGS</h2>
          <button type="button" className="btn ghost" onClick={onClose}>
            Close
          </button>
        </div>
        <p className="modal-help">
          {isNativeMode()
            ? 'Paste your Shodan API key once. It is stored in Capacitor Preferences on this device and never committed to git.'
            : 'Desktop mode uses SHODAN_API_KEY from the server .env. You can still paste a key here for local testing; it stays in localStorage.'}
        </p>
        <label className="modal-label" htmlFor="shodan-key">
          Shodan API key
        </label>
        <input
          id="shodan-key"
          className="search-input"
          type="password"
          autoComplete="off"
          spellCheck={false}
          value={key}
          onChange={(e) => setKey(e.target.value)}
          placeholder="Paste key from https://account.shodan.io/"
        />
        <div className="modal-actions">
          <button type="button" className="btn" disabled={saving} onClick={() => void save()}>
            {saving ? 'Saving…' : 'Save key'}
          </button>
          <button
            type="button"
            className="btn magenta"
            disabled={saving}
            onClick={() => {
              setKey('');
              void setApiKey('').then(() => {
                setMsg('Key cleared.');
                onSaved();
              });
            }}
          >
            Clear
          </button>
        </div>
        {msg && <div className="modal-msg">{msg}</div>}
        <p className="modal-ethics">
          Authorized reconnaissance only. Metadata search UI — no exploits, no device login.
        </p>
      </div>
    </div>
  );
}
