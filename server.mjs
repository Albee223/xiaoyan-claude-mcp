import http from "node:http";
import crypto from "node:crypto";

const PORT = Number(process.env.PORT || 10000);
const OWNER_PASSWORD = process.env.OWNER_PASSWORD || "";
const OAUTH_SIGNING_SECRET = process.env.OAUTH_SIGNING_SECRET || "";
const SITE_BASE_URL = (process.env.SITE_BASE_URL || "").replace(/\/$/, "");
const SITE_BYPASS_TOKEN = process.env.SITE_BYPASS_TOKEN || "";
const SITE_SERVICE_KEY = process.env.SITE_SERVICE_KEY || "";

const required = { OWNER_PASSWORD, OAUTH_SIGNING_SECRET, SITE_BASE_URL, SITE_BYPASS_TOKEN, SITE_SERVICE_KEY };
const missing = Object.entries(required).filter(([, value]) => !value).map(([key]) => key);
if (missing.length) console.error(`Missing required environment variables: ${missing.join(", ")}`);

const usedCodes = new Set();
const tools = [
  tool("get_xiaoyan_status", "查看小研串接狀態", "確認 Claude、資料庫與 Threads 安全鎖狀態。", {}, true),
  tool("list_daily_radar", "讀取 Daily Radar", "讀取最近一次已驗證的海巡素材。", { category: { type: "string" }, limit: { type: "integer", minimum: 1, maximum: 30, default: 10 } }, true),
  tool("list_content", "讀取文案工作區", "列出草稿、待審、已核准與已排程內容。", { status: { type: "string", enum: ["draft", "review", "approved", "scheduled", "published"] }, limit: { type: "integer", minimum: 1, maximum: 50, default: 20 } }, true),
  tool("save_draft", "儲存小研文案草稿", "為指定素材建立或更新草稿，不會發布。", { source_item_id: { type: "integer", minimum: 1 }, title: { type: "string", minLength: 1, maxLength: 180 }, content_text: { type: "string", minLength: 1, maxLength: 5000 }, source_url: { type: "string", maxLength: 1000 }, content_type: { type: "string", enum: ["copy", "share", "morning"], default: "copy" } }, false, ["source_item_id", "title", "content_text"]),
  tool("submit_for_review", "送出文案審核", "把草稿移到待審，不會核准或發布。", { content_id: { type: "integer", minimum: 1 } }, false, ["content_id"]),
  tool("approve_content", "核准文案", "核准待審文案；必須 confirmed=true，仍不會發布。", { content_id: { type: "integer", minimum: 1 }, confirmed: { type: "boolean" } }, false, ["content_id", "confirmed"]),
  tool("schedule_content", "安排文案行事曆", "只允許把已核准內容排入日期與時段。", { content_id: { type: "integer", minimum: 1 }, date: { type: "string", pattern: "^\\d{4}-\\d{2}-\\d{2}$" }, slot: { type: "string", enum: ["morning", "noon", "evening"] } }, false, ["content_id", "date", "slot"]),
  tool("list_calendar", "查看文案行事曆", "列出日期範圍內已排程的內容。", { from: { type: "string", pattern: "^\\d{4}-\\d{2}-\\d{2}$" }, to: { type: "string", pattern: "^\\d{4}-\\d{2}-\\d{2}$" } }, true),
  tool("summarize_performance", "讀取內容成效", "讀取最近的成效快照供 Claude 分析。", { limit: { type: "integer", minimum: 1, maximum: 50, default: 20 } }, true),
];

function tool(name, title, description, properties, readOnly, requiredFields = []) {
  return { name, title, description, inputSchema: { type: "object", properties, ...(requiredFields.length ? { required: requiredFields } : {}), additionalProperties: false }, annotations: { readOnlyHint: readOnly, destructiveHint: false, idempotentHint: true, openWorldHint: false } };
}

function baseUrl(req) {
  return (process.env.PUBLIC_BASE_URL || `https://${req.headers.host}`).replace(/\/$/, "");
}

function b64url(value) {
  return Buffer.from(value).toString("base64url");
}

function sign(payload) {
  const body = b64url(JSON.stringify(payload));
  const signature = crypto.createHmac("sha256", OAUTH_SIGNING_SECRET).update(body).digest("base64url");
  return `${body}.${signature}`;
}

function verify(token, expectedType) {
  const [body, signature] = String(token || "").split(".");
  if (!body || !signature) throw new Error("invalid_token");
  const expected = crypto.createHmac("sha256", OAUTH_SIGNING_SECRET).update(body).digest();
  const actual = Buffer.from(signature, "base64url");
  if (actual.length !== expected.length || !crypto.timingSafeEqual(actual, expected)) throw new Error("invalid_token");
  const payload = JSON.parse(Buffer.from(body, "base64url").toString("utf8"));
  if (payload.type !== expectedType || Number(payload.exp) < Date.now()) throw new Error("expired_token");
  return payload;
}

function safeEqual(left, right) {
  const a = Buffer.from(String(left || ""));
  const b = Buffer.from(String(right || ""));
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function json(res, status, payload, headers = {}) {
  res.writeHead(status, { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", ...headers });
  res.end(JSON.stringify(payload));
}

function html(res, status, value) {
  res.writeHead(status, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store", "X-Frame-Options": "DENY", "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'" });
  res.end(value);
}

function redirect(res, location) {
  res.writeHead(302, { Location: location, "Cache-Control": "no-store" });
  res.end();
}

async function readBody(req, limit = 100_000) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > limit) throw new Error("payload_too_large");
    chunks.push(chunk);
  }
  return Buffer.concat(chunks).toString("utf8");
}

async function bridge(action, args = {}) {
  const response = await fetch(`${SITE_BASE_URL}/api/mcp-bridge`, {
    method: "POST",
    headers: {
      "OAI-Sites-Authorization": `Bearer ${SITE_BYPASS_TOKEN}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ serviceKey: SITE_SERVICE_KEY, action, args }),
  });
  const body = await response.json().catch(() => ({ error: `invalid_site_response_${response.status}` }));
  if (!response.ok) throw new Error(body.error || `site_request_failed_${response.status}`);
  return body;
}

async function contentById(id) {
  const { records = [] } = await bridge("content.list");
  return records.find((record) => Number(record.id) === Number(id));
}

async function saveContent(record, patch = {}) {
  return bridge("content.save", { sourceItemId: record.sourceItemId, contentType: record.contentType, title: record.title, contentText: record.contentText, sourceUrl: record.sourceUrl, status: record.status, scheduledDate: record.scheduledDate, scheduledSlot: record.scheduledSlot, ...patch });
}

function toolResult(payload, isError = false) {
  return { content: [{ type: "text", text: JSON.stringify(payload, null, 2) }], structuredContent: payload, ...(isError ? { isError: true } : {}) };
}

async function callTool(name, args) {
  if (name === "get_xiaoyan_status") {
    let storage = "ready";
    try { await bridge("content.list"); } catch { storage = "unavailable"; }
    return toolResult({ claude_mcp: "ready", storage, threads_publish: "locked_pending_meta_authorization", threads_reply: "locked_pending_meta_authorization", safety: "No tool can publish or reply." });
  }
  if (name === "list_daily_radar") {
    const data = await bridge("radar.list");
    const category = String(args.category || "").trim();
    const limit = Math.max(1, Math.min(30, Number(args.limit) || 10));
    const items = (data.items || []).filter((item) => !category || item.category === category).slice(0, limit);
    return toolResult({ report_date: data.reportDate, items });
  }
  if (name === "list_content") {
    const data = await bridge("content.list", { status: args.status || "" });
    return toolResult({ records: (data.records || []).slice(0, Math.max(1, Math.min(50, Number(args.limit) || 20))) });
  }
  if (name === "save_draft") {
    const payload = { sourceItemId: Number(args.source_item_id), contentType: String(args.content_type || "copy"), title: String(args.title || ""), contentText: String(args.content_text || ""), sourceUrl: String(args.source_url || ""), status: "draft", createdBy: "claude" };
    if (!Number.isSafeInteger(payload.sourceItemId) || payload.sourceItemId < 1 || !payload.title.trim() || !payload.contentText.trim()) return toolResult({ error: "invalid_draft" }, true);
    const result = await bridge("content.save", payload);
    return toolResult({ record: result.record, next_step: "使用 submit_for_review 送交審核。" });
  }
  if (["submit_for_review", "approve_content", "schedule_content"].includes(name)) {
    const record = await contentById(args.content_id);
    if (!record) return toolResult({ error: "content_not_found" }, true);
    if (name === "submit_for_review") return toolResult({ ...(await saveContent(record, { status: "review", scheduledDate: null, scheduledSlot: null })), note: "已送審，尚未核准或發布。" });
    if (name === "approve_content") {
      if (args.confirmed !== true) return toolResult({ error: "explicit_confirmation_required" }, true);
      if (record.status !== "review") return toolResult({ error: "review_required_first", current_status: record.status }, true);
      return toolResult({ ...(await saveContent(record, { status: "approved", scheduledDate: null, scheduledSlot: null })), note: "已核准，尚未發布。" });
    }
    if (!["approved", "scheduled"].includes(record.status)) return toolResult({ error: "approval_required_first", current_status: record.status }, true);
    const date = String(args.date || "");
    const slot = String(args.slot || "");
    if (!/^\d{4}-\d{2}-\d{2}$/.test(date) || !["morning", "noon", "evening"].includes(slot)) return toolResult({ error: "invalid_schedule" }, true);
    return toolResult({ ...(await saveContent(record, { status: "scheduled", scheduledDate: date, scheduledSlot: slot })), note: "已排入行事曆；Threads 發布仍鎖定。" });
  }
  if (name === "list_calendar") {
    const data = await bridge("content.list", { from: args.from || "", to: args.to || "" });
    return toolResult({ records: (data.records || []).filter((record) => record.status === "scheduled") });
  }
  if (name === "summarize_performance") {
    const data = await bridge("performance.list");
    return toolResult({ records: (data.records || []).slice(0, Math.max(1, Math.min(50, Number(args.limit) || 20))) });
  }
  return toolResult({ error: "unknown_tool" }, true);
}

function authPage(fields, error = "") {
  const hidden = Object.entries(fields).map(([key, value]) => `<input type="hidden" name="${escapeHtml(key)}" value="${escapeHtml(value)}">`).join("");
  return `<!doctype html><html lang="zh-Hant"><meta name="viewport" content="width=device-width,initial-scale=1"><title>連接小研與 Claude</title><style>body{font-family:system-ui;background:#f5f4fb;margin:0;display:grid;place-items:center;min-height:100vh;color:#19182b}.card{width:min(420px,calc(100% - 40px));background:white;border:1px solid #ddd9ef;border-radius:24px;padding:32px;box-shadow:0 20px 60px #33276818}.mark{width:48px;height:48px;border-radius:16px;background:linear-gradient(135deg,#7b55f8,#ef7d9c);display:grid;place-items:center;color:white;font-weight:800}h1{font-size:24px;margin:20px 0 8px}p{color:#67637a;line-height:1.6}label{display:block;font-weight:700;margin:24px 0 8px}input[type=password]{box-sizing:border-box;width:100%;padding:14px 16px;border:1px solid #cbc6df;border-radius:12px;font-size:17px}button{width:100%;margin-top:18px;padding:14px;border:0;border-radius:12px;background:#6847ee;color:white;font-size:16px;font-weight:800}.error{color:#b42318;background:#fff0ee;padding:10px 12px;border-radius:10px}</style><main class="card"><div class="mark">研</div><h1>連接小研與 Claude</h1><p>授權後，Claude 可以讀取素材、建立草稿、送審及排程；不會自動發文或回覆。</p>${error ? `<p class="error">${escapeHtml(error)}</p>` : ""}<form method="post" action="/authorize">${hidden}<label for="password">小研擁有者密碼</label><input id="password" name="password" type="password" autocomplete="current-password" required autofocus><button type="submit">確認並授權</button></form></main></html>`;
}

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[char]));
}

async function handle(req, res) {
  const base = baseUrl(req);
  const url = new URL(req.url, base);
  if (req.method === "OPTIONS") return json(res, 204, {}, { "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Headers": "authorization,content-type,mcp-protocol-version", "Access-Control-Allow-Methods": "GET,POST,OPTIONS" });
  if (url.pathname === "/health") return json(res, missing.length ? 503 : 200, { status: missing.length ? "misconfigured" : "ok", missing });

  if (["/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp"].includes(url.pathname)) {
    return json(res, 200, { resource: `${base}/mcp`, authorization_servers: [base], bearer_methods_supported: ["header"], scopes_supported: ["mcp"] });
  }
  if (["/.well-known/oauth-authorization-server", "/.well-known/openid-configuration"].includes(url.pathname)) {
    return json(res, 200, { issuer: base, authorization_endpoint: `${base}/authorize`, token_endpoint: `${base}/token`, registration_endpoint: `${base}/register`, response_types_supported: ["code"], grant_types_supported: ["authorization_code"], code_challenge_methods_supported: ["S256"], token_endpoint_auth_methods_supported: ["none"], scopes_supported: ["mcp"] });
  }
  if (url.pathname === "/register" && req.method === "POST") {
    const body = JSON.parse(await readBody(req));
    const redirectUris = Array.isArray(body.redirect_uris) ? body.redirect_uris.filter((value) => /^https:\/\//.test(value)) : [];
    if (!redirectUris.length) return json(res, 400, { error: "invalid_redirect_uris" });
    const clientId = sign({ type: "client", redirect_uris: redirectUris, exp: Date.now() + 365 * 86400_000 });
    return json(res, 201, { client_id: clientId, client_id_issued_at: Math.floor(Date.now() / 1000), redirect_uris: redirectUris, grant_types: ["authorization_code"], response_types: ["code"], token_endpoint_auth_method: "none", client_name: body.client_name || "Claude" });
  }
  if (url.pathname === "/authorize" && req.method === "GET") {
    const fields = Object.fromEntries(["response_type", "client_id", "redirect_uri", "scope", "state", "code_challenge", "code_challenge_method"].map((key) => [key, url.searchParams.get(key) || ""]));
    try {
      const client = verify(fields.client_id, "client");
      if (fields.response_type !== "code" || fields.code_challenge_method !== "S256" || !client.redirect_uris.includes(fields.redirect_uri)) throw new Error("invalid_authorization_request");
      return html(res, 200, authPage(fields));
    } catch {
      return html(res, 400, "<h1>授權要求無效</h1>");
    }
  }
  if (url.pathname === "/authorize" && req.method === "POST") {
    const form = new URLSearchParams(await readBody(req));
    const fields = Object.fromEntries(["response_type", "client_id", "redirect_uri", "scope", "state", "code_challenge", "code_challenge_method"].map((key) => [key, form.get(key) || ""]));
    try {
      const client = verify(fields.client_id, "client");
      if (!client.redirect_uris.includes(fields.redirect_uri) || fields.code_challenge_method !== "S256") throw new Error("invalid_authorization_request");
      if (!safeEqual(form.get("password"), OWNER_PASSWORD)) return html(res, 401, authPage(fields, "密碼不正確，請再試一次。"));
      const nonce = crypto.randomBytes(18).toString("base64url");
      const code = sign({ type: "code", client_id: fields.client_id, redirect_uri: fields.redirect_uri, code_challenge: fields.code_challenge, nonce, exp: Date.now() + 5 * 60_000 });
      const target = new URL(fields.redirect_uri);
      target.searchParams.set("code", code);
      if (fields.state) target.searchParams.set("state", fields.state);
      return redirect(res, target.toString());
    } catch {
      return html(res, 400, "<h1>授權失敗</h1>");
    }
  }
  if (url.pathname === "/token" && req.method === "POST") {
    const form = new URLSearchParams(await readBody(req));
    try {
      if (form.get("grant_type") !== "authorization_code") throw new Error("unsupported_grant_type");
      const code = form.get("code");
      const payload = verify(code, "code");
      if (usedCodes.has(payload.nonce)) throw new Error("code_already_used");
      if (payload.client_id !== form.get("client_id") || payload.redirect_uri !== form.get("redirect_uri")) throw new Error("invalid_grant");
      const verifier = form.get("code_verifier") || "";
      const challenge = crypto.createHash("sha256").update(verifier).digest("base64url");
      if (!safeEqual(challenge, payload.code_challenge)) throw new Error("invalid_code_verifier");
      usedCodes.add(payload.nonce);
      const accessToken = sign({ type: "access", sub: "xiaoyan-owner", scope: "mcp", exp: Date.now() + 30 * 86400_000 });
      return json(res, 200, { access_token: accessToken, token_type: "Bearer", expires_in: 30 * 86400, scope: "mcp" });
    } catch (error) {
      return json(res, 400, { error: "invalid_grant", error_description: error.message });
    }
  }
  if (url.pathname === "/mcp") {
    try {
      const match = String(req.headers.authorization || "").match(/^Bearer\s+(.+)$/i);
      verify(match?.[1], "access");
    } catch {
      return json(res, 401, { error: "unauthorized" }, { "WWW-Authenticate": `Bearer resource_metadata="${base}/.well-known/oauth-protected-resource/mcp"` });
    }
    if (req.method === "GET") {
      return json(res, 405, { error: "method_not_allowed", message: "Use POST for MCP requests." }, { Allow: "POST" });
    }
    if (req.method !== "POST") {
      return json(res, 405, { error: "method_not_allowed" }, { Allow: "POST" });
    }
    const rpc = JSON.parse(await readBody(req));
    if (String(rpc.method || "").startsWith("notifications/")) { res.writeHead(202); return res.end(); }
    if (rpc.jsonrpc !== "2.0" || !rpc.method) return json(res, 400, { jsonrpc: "2.0", id: rpc.id ?? null, error: { code: -32600, message: "Invalid Request" } });
    if (rpc.method === "initialize") return json(res, 200, { jsonrpc: "2.0", id: rpc.id, result: { protocolVersion: "2025-06-18", capabilities: { tools: { listChanged: false } }, serverInfo: { name: "xiaoyan-claude-mcp", version: "1.0.0" }, instructions: "小研營運工具：可讀素材、建立草稿、送審、核准與排程；目前不提供 Threads 自動發布或自動回覆。" } });
    if (rpc.method === "ping") return json(res, 200, { jsonrpc: "2.0", id: rpc.id, result: {} });
    if (rpc.method === "tools/list") return json(res, 200, { jsonrpc: "2.0", id: rpc.id, result: { tools } });
    if (rpc.method === "tools/call") {
      try {
        const result = await callTool(rpc.params?.name, rpc.params?.arguments || {});
        return json(res, 200, { jsonrpc: "2.0", id: rpc.id, result });
      } catch (error) {
        return json(res, 200, { jsonrpc: "2.0", id: rpc.id, result: toolResult({ error: "tool_execution_failed", message: error.message }, true) });
      }
    }
    return json(res, 404, { jsonrpc: "2.0", id: rpc.id ?? null, error: { code: -32601, message: "Method not found" } });
  }
  if (url.pathname === "/") return html(res, 200, "<h1>小研 Claude MCP</h1><p>服務已啟用。請從 Claude 的自訂連接器新增此服務。</p>");
  return json(res, 404, { error: "not_found" });
}

const server = http.createServer((req, res) => handle(req, res).catch((error) => {
  console.error(error);
  json(res, 500, { error: "internal_error" });
}));

server.listen(PORT, "0.0.0.0", () => console.log(`Xiaoyan Claude MCP listening on ${PORT}`));
