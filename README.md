# SHODAN RECON

Third-party Shodan search UI for **authorized reconnaissance only**. Natural-language queries are translated into Shodan filter syntax (heuristic, no LLM required). Results are honeypot-filtered and ranked by interestingness.

> **Ethics / authorized use:** This app only searches Shodan’s legitimate API and displays returned metadata, banners, and shodan.io links. It does **not** log into devices, stream webcams, or run exploits. Accessing systems without permission is illegal. You must supply **your own** Shodan API key.

## Stack

| Surface | How it works |
|---------|----------------|
| **Desktop (web)** | Vite + React client → local Express proxy (`:8787`) → `api.shodan.io`. Key stays in server `.env`. |
| **Android APK** | Capacitor WebView. NL translator, honeypot filter, ranking, and dork library run **in-app**. Shodan calls use `@capacitor/core` **CapacitorHttp** (bypasses CORS). API key stored in **Capacitor Preferences** (Settings screen). |

- **App ID:** `com.rcullens.shodanrecon`
- **App name:** Shodan Recon

## Desktop setup

```bash
cp .env.example .env
# Edit .env — set SHODAN_API_KEY=your_key_here  (never commit .env)

npm run install:all   # or: npm i && npm i --prefix server && npm i --prefix client
npm run dev
```

- UI: http://localhost:5173  
- API: http://localhost:8787  

```bash
npm run build   # production client + server build
```

Keys live in `.env` / `.env.local` (gitignored). On desktop the browser never embeds the key; all Shodan calls go through `/api/*`.

## Android APK (sideload)

### Prebuilt debug APK

Download `shodan-recon-debug.apk` from the GitHub **Releases** page (or copy from `dist-apk/` after a local build).

### Install on a phone/tablet

1. Transfer the APK to the device (USB, Drive, etc.).
2. Enable **Install unknown apps** / allow your file manager or browser to install APKs (Settings → Security / Apps).
3. Open the APK and install **Shodan Recon**.
4. Launch the app → tap **SETTINGS** → paste your Shodan API key from https://account.shodan.io/ → **Save key**.
5. Run searches / recon / dork library as on desktop.

This is a **debug** APK (debug-signed). Fine for personal sideload; not Play Store–ready. Release signing is optional later.

### Build the APK yourself

Requirements: Node 20+, JDK 17+ (21 OK), Android SDK (platform 35, build-tools).

```bash
export ANDROID_HOME=/path/to/android-sdk   # or use /workspace/android-sdk on this box
export JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64   # adjust
export PATH="$JAVA_HOME/bin:$ANDROID_HOME/cmdline-tools/latest/bin:$PATH"

cd client
npm install
npm run build
npx cap sync android
cd android
./gradlew assembleDebug
```

APK output:

```text
client/android/app/build/outputs/apk/debug/app-debug.apk
```

Copy to a clear path:

```bash
mkdir -p ../dist-apk
cp app/build/outputs/apk/debug/app-debug.apk ../../dist-apk/shodan-recon-debug.apk
```

Or from repo root after deps are installed: `npm run build:apk` (runs client sync + gradle).

## What works where

| Feature | Desktop | Android APK |
|---------|---------|-------------|
| Paste / store API key | Server `.env` (Settings also writes localStorage) | **SETTINGS** → Capacitor Preferences |
| NL → Shodan translate | Via Express | In-app shared module |
| Recon / search / host detail | Via Express proxy | CapacitorHttp → api.shodan.io |
| Dork library browse | Via `/api/dorks` | Bundled `dorks.json` |
| Credits / plan pill | `/api/info` | Direct `/api-info` |
| Honeypot filter + ranking | Server | In-app shared modules |
| Express Node server | Required | **Not used** |

## Environment (desktop)

| Variable | Required | Description |
|----------|----------|-------------|
| `SHODAN_API_KEY` | Yes (live search) | From https://account.shodan.io/ |
| `PORT` | No | Backend port (default `8787`) |

## Features

- Heuristic NL → Shodan (city/state/country, device profiles)
- Creative query variants + community dork library (~548 entries)
- Official Shodan REST search (rate-polite multi-variant)
- Credit/plan display
- Honeypot filter + interestingness ranking
- Dark hacker / cyberpunk UI

## Dork library

Sources ingested into `server/data/dorks.json` (also bundled for Android under `client/src/shared/data/`):

1. Lothos basic filters / device dorks  
2. Lothos extended markdown catalog  
3. ICS/SCADA vendor CSV  
4. Admin / infra catalog  

Re-ingest: `python3 server/scripts/ingest-dorks.py` then copy JSON into `client/src/shared/data/` if you need the APK updated.

## License / use

Use only with your own Shodan account and only for systems you are authorized to recon. Authors assume no liability for misuse.
