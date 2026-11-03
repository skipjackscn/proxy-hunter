# Proxy Hunter

A scope-limited proxy verification tool for IPv4 CIDR ranges that you own or are explicitly authorized to assess.

## Features

- GitHub Actions scan every 6 hours (UTC) and manual workflow dispatch.
- Explicit CIDR allowlist and approved-port list; empty scope means no scan.
- Hard limits for host count, concurrency, request rate and timeouts.
- Verifies SOCKS5 (no-auth), HTTP CONNECT and HTTPS-proxy (TLS + CONNECT) by making a real HTTPS request through the candidate.
- Records latency and observed egress IP.
- Exports JSON, CSV and protocol-specific TXT lists, including fastest 50/100/500.
- Dashboard deployable to GitHub Pages or Cloudflare Workers.
- Optional authenticated Worker endpoint to dispatch a GitHub Actions scan.

> **Authorization and safety:** configure only CIDR ranges for which you own the network or have written authorization. This is not a general public-Internet scanner. Do not import arbitrary public ranges. Treat discovered open proxies as untrusted; never send credentials or sensitive traffic through them.

## 1. Configure your authorized scope

Edit `config/cidrs.txt`, one IPv4 CIDR per line. The file is intentionally empty in the initial commit. Edit `config/ports.txt` to include only ports approved for testing.

Then edit `config/settings.json` and set `authorized_scope_ack` to `true` after confirming authorization. The default cap is 256 hosts per run. The scanner refuses to run with an empty CIDR list or without the acknowledgement.

## 2. Enable GitHub Actions and Pages

1. Open **Settings → Actions → General** and allow GitHub Actions to read and write repository contents.
2. Open **Settings → Pages** and select **GitHub Actions** as the build and deployment source.
3. The workflow `.github/workflows/scan.yml` runs every six hours (UTC); you can also use **Actions → Proxy Hunter Scan → Run workflow**.
4. Configure only approved CIDRs and ports before starting a scan.

The workflow commits scan output and deploys the dashboard from `public/`. GitHub scheduled workflows can be delayed during busy periods.

## 3. Run locally

Python 3.11+ (3.12 recommended):

```bash
python -m venv .venv
# Windows: .venv\\Scripts\\activate
# Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt
python -m proxyhunter --config config/settings.json
```

## 4. Cloudflare Worker dashboard

The Worker serves the same static dashboard and exposes:
- `GET /api/health`
- `GET /api/data` and `GET /api/history`
- `POST /api/scan` (requires the `PANEL_API_TOKEN` secret)

Set `GITHUB_OWNER=skipjackscn` and `GITHUB_REPO=proxy-hunter` in `wrangler.toml`. Then:

```bash
npm install
npx wrangler secret put GITHUB_TOKEN
npx wrangler secret put PANEL_API_TOKEN
npx wrangler deploy
```

Use a fine-grained GitHub token restricted to this repository with **Actions: write** permission. Never put tokens in browser code or commit them.

For automatic Worker deployment from GitHub Actions, add repository secrets `CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_ACCOUNT_ID`. Without these secrets, Pages deployment still works and Worker deployment is skipped.

## 5. Output files

The scanner writes `data/results/latest.json`, `data/results/history.json`, and exports under `output/`:
`socks5.txt`, `http.txt`, `https.txt`, `all-proxies.txt`, `fastest-50.txt`, `fastest-100.txt`, `fastest-500.txt`, `proxies.json`, and `proxies.csv`.

URI format: `socks5://IP:PORT`, `http://IP:PORT`, or `https://IP:PORT`. This version checks unauthenticated proxies only.

## Operational notes

- GitHub-hosted runners may not reach private networks. For private authorized CIDRs, use a self-hosted runner inside that network and review the security implications.
- GitHub-hosted runner egress IPs are not fixed by default; account for this in firewall rules.
- A proxy can stop working immediately after a successful check. Use `checked_at` as freshness metadata.
- The Cloudflare Worker is a dashboard/control plane; it does not perform TCP scans or relay proxy traffic.
