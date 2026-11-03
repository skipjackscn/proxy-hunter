const JSON_HEADERS = { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" };

function json(data, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: JSON_HEADERS });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === "/api/health" && request.method === "GET") {
      return json({ ok: true, service: "Proxy Hunter API" });
    }
    if ((url.pathname === "/api/data" || url.pathname === "/api/history") && request.method === "GET") {
      const owner = env.GITHUB_OWNER;
      const repo = env.GITHUB_REPO;
      if (!owner || !repo) return json({ error: "Configure GITHUB_OWNER and GITHUB_REPO in Worker settings" }, 503);
      const file = url.pathname === "/api/history" ? "history.json" : "latest.json";
      const raw = `https://raw.githubusercontent.com/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/main/data/results/${file}`;
      const response = await fetch(raw, { headers: { "accept": "application/json" }, cf: { cacheTtl: 30, cacheEverything: true } });
      if (!response.ok) return json({ error: "No scan result is published yet", upstream_status: response.status }, 404);
      return new Response(response.body, { headers: { "content-type": "application/json; charset=utf-8", "cache-control": "public, max-age=30" } });
    }
    if (url.pathname === "/api/scan" && request.method === "POST") {
      if (!env.PANEL_API_TOKEN || request.headers.get("x-panel-token") !== env.PANEL_API_TOKEN) {
        return json({ error: "Unauthorized" }, 401);
      }
      if (!env.GITHUB_TOKEN || !env.GITHUB_OWNER || !env.GITHUB_REPO) return json({ error: "Worker GitHub settings are incomplete" }, 503);
      const workflow = env.GITHUB_WORKFLOW || "scan.yml";
      const endpoint = `https://api.github.com/repos/${encodeURIComponent(env.GITHUB_OWNER)}/${encodeURIComponent(env.GITHUB_REPO)}/actions/workflows/${encodeURIComponent(workflow)}/dispatches`;
      const dispatch = await fetch(endpoint, {
        method: "POST",
        headers: {
          "authorization": `Bearer ${env.GITHUB_TOKEN}`,
          "accept": "application/vnd.github+json",
          "content-type": "application/json",
          "x-github-api-version": "2022-11-28",
          "user-agent": "Proxy-Hunter-Worker"
        },
        body: JSON.stringify({ ref: "main" })
      });
      if (dispatch.status !== 204) return json({ error: "GitHub workflow dispatch failed", status: dispatch.status }, 502);
      return json({ ok: true, message: "Scan workflow dispatched" }, 202);
    }
    if (url.pathname.startsWith("/api/")) return json({ error: "Not found" }, 404);
    return env.ASSETS.fetch(request);
  }
};
