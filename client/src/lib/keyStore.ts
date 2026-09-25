import { Capacitor } from '@capacitor/core';
import { Preferences } from '@capacitor/preferences';

const KEY = 'shodan_api_key';

export async function getApiKey(): Promise<string> {
  if (Capacitor.isNativePlatform()) {
    const { value } = await Preferences.get({ key: KEY });
    return (value || '').trim();
  }
  try {
    return (localStorage.getItem(KEY) || '').trim();
  } catch {
    return '';
  }
}

export async function setApiKey(key: string): Promise<void> {
  const v = key.trim();
  if (Capacitor.isNativePlatform()) {
    if (v) await Preferences.set({ key: KEY, value: v });
    else await Preferences.remove({ key: KEY });
    return;
  }
  try {
    if (v) localStorage.setItem(KEY, v);
    else localStorage.removeItem(KEY);
  } catch {
    /* ignore */
  }
}

export async function hasApiKey(): Promise<boolean> {
  return Boolean(await getApiKey());
}
