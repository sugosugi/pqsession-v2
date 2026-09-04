// pqsession 中继服务器 v2：仍是“哑管道”，只在两端之间转发不透明密文。
// 它永远看不到私钥、会话密钥或明文；端到端加密由浏览器完成。
//
// 运行：  npm install   然后   npm start        （默认监听 0.0.0.0:8080）
// 自检：  node server.js --check                （不启动服务：校验前端 CSP 哈希、本地算法库、配置）
// 固定库：npm run vendor                         （把 ML-KEM / hash-wasm 下载到 ./vendor 并打印 SHA-256；
//                                                之后启动时 CSP 会自动把 esm.sh 从 script-src 移除）
//
// v2 相对 v1.2 的加固（全部不改动端到端密码学）：
//   1. 修复致命崩溃：任意客户端发送 JSON 字面量 null，旧版 msg.t 会抛 TypeError，
//      异常从 ws 的 message 事件冒泡为未捕获异常，整个进程退出。一帧即可打死中继。
//   2. 端到端背压：接收方读得慢时暂停发送方 socket，而不是让服务器无限缓冲密文（内存型 DoS）；
//      长时间不读的一端判定为僵死并踢出，释放 1 对 1 房间。
//   3. 字节级整形限速：旧版只限“消息条数”，4 MiB 大帧 x 2000 条/秒 仍可打满内存与带宽。
//      超额不再丢帧（丢帧会让文件传输悄悄失败），而是暂停读取该连接“把欠的时间补回来”。
//   4. 安全默认值：Origin 默认仅同源；每 IP 与全局并发连接上限；未入房间的连接限时清理；
//      关闭 permessage-deflate（密文不可压缩，且避免 zlib 内存放大与压缩侧信道）。
//   5. CSP 哈希启动时从实际 HTML 计算，并与页内 <meta> 比对，不一致直接拒绝启动，
//      杜绝“哈希失配 → 有人图省事改成 unsafe-inline”的经典事故。
//   6. 可选原生 TLS（TLS_CERT / TLS_KEY），开启即自动加 HSTS；纯 HTTP 暴露到非回环地址时醒目警告
//      （浏览器在非安全上下文里根本不提供 crypto.subtle 与麦克风，本页无法工作）。
//   7. 只接受 GET / HEAD；请求头与超时收紧；不记录任何每连接日志（元数据最小化）。
//
// 注意：'ws' 仅在作为主服务器运行时动态加载（见文件末尾），
// 这样在不安装 ws 的环境里也能 import 本文件来单元测试纯逻辑（makeHub 等）。
import http from "node:http";
import https from "node:https";
import fs from "node:fs";
import path from "node:path";
import url from "node:url";
import crypto from "node:crypto";

function envInt(v, d) {
  if (v === undefined || v === null || v === "") return d;
  const n = parseInt(v, 10);
  return Number.isFinite(n) && n >= 0 ? n : d;
}
function envBool(v) { return /^(1|true|yes|on)$/i.test(String(v || "")); }
function envList(v) { return String(v || "").split(",").map((s) => s.trim()).filter(Boolean); }

export const ROOT = path.dirname(url.fileURLToPath(import.meta.url));
export const HTML_FILE = "pqsession-net.html";
export const VENDOR_FILES = ["ml-kem.mjs", "hash-wasm.mjs"];   // 与前端 loadLib() 的本地路径一一对应

export function readConfig(env = process.env) {
  return {
    PORT: env.PORT || 8080,
    HOST: env.HOST || "0.0.0.0",
    MAX_ROOM: 2,                                                   // 1 对 1：每房间最多 2 人
    MAX_PAYLOAD: envInt(env.MAX_PAYLOAD, 4 * 1024 * 1024),         // 单帧上限（前端每块约 0.7 MiB）
    MSG_RATE: envInt(env.MSG_RATE, 2000),                          // 每连接消息条数：令牌/秒
    MSG_BURST: envInt(env.MSG_BURST, 4000),                        // 突发桶容量
    BYTES_RATE: envInt(env.BYTES_RATE, 32 * 1024 * 1024),          // 每连接字节整形：字节/秒（0=不限）
    BYTES_BURST: envInt(env.BYTES_BURST, 96 * 1024 * 1024),        // 字节突发桶
    BP_HIGH: envInt(env.BP_HIGH, 8 * 1024 * 1024),                 // 背压高水位：对端发送缓冲超过即暂停来源
    BP_LOW: envInt(env.BP_LOW, 1 * 1024 * 1024),                   // 背压低水位：降到以下才恢复
    BP_STALL_MS: envInt(env.BP_STALL_MS, 60000),                   // 对端持续不读超过此时长即判僵死踢出
    MAX_CONN_IP: envInt(env.MAX_CONN_PER_IP, 64),                  // 每 IP 并发连接上限（0=不限）
    MAX_CONN: envInt(env.MAX_CONN, 4096),                          // 全局并发连接上限（0=不限）
    JOIN_TIMEOUT_MS: envInt(env.JOIN_TIMEOUT_MS, 30000),           // 连接后迟迟不 join 的清理时限（0=不限）
    HEARTBEAT_MS: envInt(env.HEARTBEAT_MS, 30000),                 // 心跳间隔（0=关闭）
    TRUST_PROXY: envBool(env.TRUST_PROXY),                         // 置于反向代理后才开：信任 X-Forwarded-*
    ALLOWED_ORIGINS: envList(env.ALLOWED_ORIGINS),                 // 空=仅同源；"*"=任意；否则同源+列表
    TLS_CERT: env.TLS_CERT || "",
    TLS_KEY: env.TLS_KEY || "",
    VENDOR_DIR: env.VENDOR_DIR || path.join(ROOT, "vendor"),
  };
}

/* ---------------------------------------------------------------------------
 * 纯中继逻辑（不依赖 ws，便于单元测试）
 * client 只需具备 .send(string[, cb]) 方法与可写的 .room 字段；
 * 若具备 .bufferedAmount / .pause() / .resume()（ws 8.12+）则自动启用背压。
 * 关键不变量：relay() 不解析 d，只按房间把它原样转发给“另一端”。
 * ------------------------------------------------------------------------- */
export function makeHub({ maxRoom = 2, bpHigh = 8 * 1024 * 1024, bpLow = 1024 * 1024, now = Date.now } = {}) {
  const rooms = new Map();                       // room -> Set<client>
  const peersOf = (room) => rooms.get(room) || new Set();

  function safeSend(client, obj) { try { client.send(JSON.stringify(obj)); } catch {} }
  function bufferedOf(c) { return typeof c.bufferedAmount === "number" ? c.bufferedAmount : 0; }

  // 暂停 / 恢复读取。多个原因（背压 bp、整形 shape）可同时成立，全部解除才真正恢复。
  function hold(c, reason) {
    if (!c.holds) c.holds = new Set();
    c.holds.add(reason);
    if (c.hubPaused) return;
    c.hubPaused = true;
    try {
      if (typeof c.pause === "function") c.pause();
      else if (c._socket && typeof c._socket.pause === "function") c._socket.pause();
    } catch {}
  }
  function release(c, reason) {
    if (!c.holds) return;
    c.holds.delete(reason);
    if (c.holds.size > 0 || !c.hubPaused) return;
    c.hubPaused = false;
    try {
      if (typeof c.resume === "function") c.resume();
      else if (c._socket && typeof c._socket.resume === "function") c._socket.resume();
    } catch {}
  }

  // 背压：client 正在把数据发给 p，而 p 的发送缓冲已过高水位 → 暂停 client 的读取，等 p 排空。
  function waitOn(client, p) {
    if (!p.bpWaiters) p.bpWaiters = new Set();
    p.bpWaiters.add(client);
    if (typeof client.bpSince !== "number") client.bpSince = now();
    client.bpWaitOn = p;
    hold(client, "bp");
  }
  function releaseWaiters(p) {
    if (!p.bpWaiters) return;
    for (const c of p.bpWaiters) { c.bpWaitOn = null; c.bpSince = null; release(c, "bp"); }
    p.bpWaiters.clear();
  }
  // 发送回调：p 的一帧已写出；若缓冲已降到低水位，恢复所有在等 p 的来源。
  function onDrain(p) {
    if (!p.bpWaiters || p.bpWaiters.size === 0) return;
    if (bufferedOf(p) > bpLow) return;
    releaseWaiters(p);
  }

  function join(client, room) {
    if (typeof room !== "string" || !room) return { ok: false, reason: "bad-room" };
    room = room.slice(0, 64);
    if (client.room) leave(client);
    const set = rooms.get(room) || new Set();
    if (set.size >= maxRoom) return { ok: false, reason: "full" };
    set.add(client); rooms.set(room, set); client.room = room;
    for (const p of set) if (p !== client) safeSend(p, { t: "peer", event: "join", n: set.size });
    return { ok: true, n: set.size };
  }

  function leave(client) {
    // 无论是否在房间内，都先解开与背压相关的所有牵连
    releaseWaiters(client);
    if (client.bpWaitOn && client.bpWaitOn.bpWaiters) client.bpWaitOn.bpWaiters.delete(client);
    client.bpWaitOn = null; client.bpSince = null;
    const room = client.room; if (!room) return;
    const set = rooms.get(room);
    if (set) {
      set.delete(client);
      for (const p of set) safeSend(p, { t: "peer", event: "leave", n: set.size });
      if (set.size === 0) rooms.delete(room);
    }
    client.room = null;
  }

  // 把 d 原样转发给同房间的其他人；服务器不读取、不存储 d。
  function relay(client, d) {
    const set = rooms.get(client.room); if (!set) return 0;
    const payload = JSON.stringify({ t: "sig", d });
    let n = 0;
    for (const p of set) {
      if (p === client) continue;
      n++;
      try { p.send(payload, () => onDrain(p)); } catch { continue; }
      if (bufferedOf(p) > bpHigh) waitOn(client, p);
    }
    return n;
  }

  return { join, leave, relay, rooms, peersOf, hold, release };
}

/* ---------------------------------------------------------------------------
 * 消息条数限流（令牌桶，每连接一个；便于单元测试）。
 * take(now) 在桶内有令牌时消耗 1 个并返回 true，否则返回 false（超额消息直接丢弃）。
 * ------------------------------------------------------------------------- */
export function makeRateLimiter({ ratePerSec = 2000, burst = 4000 } = {}) {
  let tokens = burst;
  let last = Date.now();
  return {
    take(now = Date.now()) {
      const dt = Math.max(0, now - last) / 1000;
      last = now;
      tokens = Math.min(burst, tokens + dt * ratePerSec);
      if (tokens >= 1) { tokens -= 1; return true; }
      return false;
    },
  };
}

/* ---------------------------------------------------------------------------
 * 字节整形（令牌桶允许透支）：consume(n) 返回“需要暂停读取多少毫秒才能把透支补回来”，
 * 0 表示无需暂停。与丢帧不同，整形不会让合法的大文件传输失败，只是把速率压到上限。
 * ------------------------------------------------------------------------- */
export function makeByteShaper({ bytesPerSec = 0, burst = 0 } = {}) {
  let tokens = burst;
  let last = Date.now();
  return {
    consume(n, now = Date.now()) {
      if (bytesPerSec <= 0) return 0;
      const dt = Math.max(0, now - last) / 1000;
      last = now;
      tokens = Math.min(burst, tokens + dt * bytesPerSec) - n;
      if (tokens >= 0) return 0;
      return Math.ceil((-tokens / bytesPerSec) * 1000);
    },
  };
}

/* ---------------------------------------------------------------------------
 * 心跳清扫（纯逻辑，便于单元测试）：
 *   • 上一轮未回 pong 的连接直接终止；其余标记为“待回应”并发送 ping。
 *   • 背压僵死：某连接被对端拖住（bpSince）超过 stallMs，说明对端长时间不读 → 终止对端，
 *     它的 close 会触发 leave() 并释放来源。防止半开 / 僵尸连接长期占用 1 对 1 房间。
 * client 只需具备 isAlive 字段与 ping()/terminate() 方法。
 * ------------------------------------------------------------------------- */
export function heartbeatSweep(clients, { now = Date.now(), stallMs = 0 } = {}) {
  let pinged = 0, killed = 0, stalled = 0;
  const stalledPeers = new Set();
  if (stallMs > 0) {
    for (const c of clients) {
      if (typeof c.bpSince === "number" && c.bpWaitOn && now - c.bpSince > stallMs) stalledPeers.add(c.bpWaitOn);
    }
  }
  for (const c of clients) {
    if (stalledPeers.has(c)) { stalled++; try { c.terminate(); } catch {} continue; }
    // 被本中继主动暂停读取的连接（背压 / 整形）读不到 pong，不能据此判死；它恢复后再照常心跳。
    if (c.hubPaused) { c.isAlive = true; continue; }
    if (c.isAlive === false) { killed++; try { c.terminate(); } catch {} continue; }
    c.isAlive = false; pinged++; try { c.ping(); } catch {}
  }
  return stallMs > 0 ? { pinged, killed, stalled } : { pinged, killed };   // 旧签名返回值形状不变
}

/* ---------------------------------------------------------------------------
 * Origin 策略（纯逻辑，便于单元测试）。
 *   allowed 为空  → 仅允许 Origin 的 host 与本次请求的 Host 一致（同源托管的默认拓扑）；
 *   含 "*"       → 允许任意 Origin（旧版默认行为，需显式打开）；
 *   否则          → 同源 或 列表内的精确 origin（如 https://chat.example.com）。
 * 没有 Origin 头的连接（非浏览器客户端）在非 "*" 模式下一律拒绝。
 * 这不是保密边界（Origin 可被非浏览器伪造），它挡的是“别的网站在用户浏览器里悄悄用你的中继”。
 * ------------------------------------------------------------------------- */
export function makeOriginPolicy(allowed = [], { trustProxy = false } = {}) {
  const any = allowed.includes("*");
  const list = allowed.filter((o) => o !== "*").map(normalizeOrigin).filter(Boolean);
  return function originAllowed(req) {
    if (any) return true;
    const o = req.headers && req.headers["origin"];
    if (typeof o !== "string" || !o || o === "null") return false;
    let u;
    try { u = new URL(o); } catch { return false; }
    if (u.protocol !== "http:" && u.protocol !== "https:") return false;
    if (list.includes(u.origin.toLowerCase())) return true;
    const reqHost = requestHost(req, trustProxy);
    return !!reqHost && u.host.toLowerCase() === reqHost.toLowerCase();
  };
}
export function normalizeOrigin(s) {
  try { return new URL(String(s).trim()).origin.toLowerCase(); } catch { return ""; }
}
export function requestHost(req, trustProxy) {
  const h = req.headers || {};
  if (trustProxy) {
    const xfh = String(h["x-forwarded-host"] || "").split(",")[0].trim();
    if (xfh) return xfh;
  }
  return String(h["host"] || "").trim();
}
export function clientIp(req, trustProxy) {
  if (trustProxy) {
    const xff = String(req.headers["x-forwarded-for"] || "").split(",")[0].trim();
    if (xff) return xff;
  }
  return (req.socket && req.socket.remoteAddress) || "unknown";
}

/* ---------------------------------------------------------------------------
 * 每连接消息处理（纯逻辑，便于单元测试）。
 * ws 只需是 EventEmitter 风格对象：on("message"|"pong"|"close"|"error")、send()、close()。
 * 所有输入都视为敌对：非对象 JSON（含 null）、非文本帧、缺字段一律静默丢弃，绝不抛出。
 * ------------------------------------------------------------------------- */
export function makeConnectionHandler({ hub, cfg, now = Date.now, setTimer = setTimeout, clearTimer = clearTimeout }) {
  return function onConnection(ws) {
    ws.room = null; ws.isAlive = true;
    const msgBucket = makeRateLimiter({ ratePerSec: cfg.MSG_RATE, burst: cfg.MSG_BURST });
    const shaper = makeByteShaper({ bytesPerSec: cfg.BYTES_RATE, burst: cfg.BYTES_BURST });
    let shapeTimer = null;
    const joinTimer = cfg.JOIN_TIMEOUT_MS > 0
      ? setTimer(() => { if (!ws.room) { try { ws.close(1008, "join timeout"); } catch {} } }, cfg.JOIN_TIMEOUT_MS)
      : null;

    ws.on("pong", () => { ws.isAlive = true; });

    ws.on("message", (raw, isBinary) => {
      if (isBinary) return;                                   // 协议只用文本 JSON 帧
      const len = typeof raw === "string" ? Buffer.byteLength(raw) : (raw && raw.length) || 0;
      const t = now();
      if (!msgBucket.take(t)) return;                          // 消息洪水：丢弃
      const wait = shaper.consume(len, t);                     // 字节整形：暂停读取，不丢帧
      if (wait > 0 && !shapeTimer) {
        hub.hold(ws, "shape");
        shapeTimer = setTimer(() => { shapeTimer = null; hub.release(ws, "shape"); }, wait);
      }
      let msg;
      try { msg = JSON.parse(typeof raw === "string" ? raw : raw.toString("utf8")); } catch { return; }
      if (msg === null || typeof msg !== "object" || Array.isArray(msg)) return;   // v1 崩溃点：null.t
      if (msg.t === "join") {
        const r = hub.join(ws, msg.room);
        if (!r.ok) { if (r.reason === "full") { try { ws.send(JSON.stringify({ t: "full" })); } catch {} } return; }
        try { ws.send(JSON.stringify({ t: "joined", n: r.n })); } catch {}
        return;
      }
      if (msg.t === "sig") {
        if (!ws.room || msg.d === undefined) return;
        hub.relay(ws, msg.d);
      }
    });

    const cleanup = () => {
      if (joinTimer) clearTimer(joinTimer);
      if (shapeTimer) { clearTimer(shapeTimer); shapeTimer = null; }
      hub.leave(ws);
    };
    ws.on("close", cleanup);
    ws.on("error", cleanup);
  };
}

/* ---------------------------------------------------------------------------
 * 内容安全策略与静态资源。
 *   • 内联脚本哈希从实际 HTML 计算（与浏览器算法一致：<script> 标签之间的原始文本做 SHA-256）。
 *   • 页内 <meta> CSP 必须包含同一哈希（浏览器取二者交集），不一致则拒绝启动。
 *   • 本地 vendor/ 齐全时把 https://esm.sh 从 script-src 移除：运行时不再依赖任何第三方 CDN。
 *   • frame-ancestors 只能由响应头设置（防第三方 iframe 嵌套 → 点击劫持 / 诱导误确认指纹）。
 * ------------------------------------------------------------------------- */
export function inlineScriptHashes(html) {
  const re = /<script\b[^>]*>([\s\S]*?)<\/script>/gi;
  const out = []; let m;
  while ((m = re.exec(html))) {
    out.push("sha256-" + crypto.createHash("sha256").update(m[1], "utf8").digest("base64"));
  }
  return out;
}
export function metaCspOf(html) {
  // content 里会出现单引号（'none'、'sha256-…'），因此按开头引号配对匹配
  const m = html.match(/<meta\s+http-equiv=(["'])Content-Security-Policy\1\s+content=(["'])([\s\S]*?)\2/i);
  return m ? m[3] : null;
}
export function buildCsp({ scriptHashes = [], allowCdn = true } = {}) {
  const script = ["'self'", "'wasm-unsafe-eval'", "blob:"];
  if (allowCdn) script.push("https://esm.sh");
  for (const h of scriptHashes) script.push(`'${h}'`);
  return [
    "default-src 'none'",
    `script-src ${script.join(" ")}`,
    "style-src 'unsafe-inline'",
    "img-src data:",
    "connect-src 'self' ws: wss:",
    "media-src 'none'",
    "object-src 'none'",
    "base-uri 'none'",
    "form-action 'none'",
    "frame-ancestors 'none'",
  ].join("; ");
}

// 启动期准备：读取并冻结静态资源（之后只从内存提供，磁盘被改也不会“边改边发”），返回诊断信息。
export function prepareAssets({ root = ROOT, vendorDir = path.join(ROOT, "vendor") } = {}) {
  const errors = [], warnings = [], info = [];
  const assets = new Map();
  const htmlPath = path.join(root, HTML_FILE);
  let html;
  try { html = fs.readFileSync(htmlPath); } catch (e) { errors.push(`读不到前端文件 ${htmlPath}: ${e.message}`); return { errors, warnings, info, assets, csp: "", hashes: [], allowCdn: true }; }
  const htmlText = html.toString("utf8");
  const hashes = inlineScriptHashes(htmlText);
  if (hashes.length === 0) warnings.push("前端 HTML 里没有找到内联 <script>，CSP 将不含脚本哈希。");
  const meta = metaCspOf(htmlText);
  if (meta === null) {
    warnings.push("前端 HTML 缺少 <meta http-equiv=\"Content-Security-Policy\">，file:// 直接打开时将没有 CSP 防护。");
  } else {
    for (const h of hashes) if (!meta.includes(h)) errors.push(`前端 <meta> CSP 未包含内联脚本的当前哈希 '${h}'。你改动了内联脚本但没有更新 <meta>。请把该哈希写入 <meta>（不要用 'unsafe-inline' 代替）。`);
    const scriptDirective = meta.split(";").find((d) => /^\s*script-src\b/.test(d)) || "";
    if (/unsafe-inline/.test(scriptDirective)) errors.push("前端 <meta> CSP 的 script-src 含 'unsafe-inline'，这会瓦解注入防护，拒绝启动。");
  }
  assets.set("/", { body: html, type: "text/html; charset=utf-8" });
  assets.set("/" + HTML_FILE, { body: html, type: "text/html; charset=utf-8" });
  for (const h of hashes) info.push(`内联脚本哈希 ${h}`);

  const present = [], missing = [];
  for (const name of VENDOR_FILES) {
    const p = path.join(vendorDir, name);
    let body;
    try { body = fs.readFileSync(p); } catch { missing.push(name); continue; }
    const sha = crypto.createHash("sha256").update(body).digest("hex");
    if (body.length < 1000 || /^\s*</.test(body.subarray(0, 64).toString("utf8"))) {
      errors.push(`vendor/${name} 看起来不是 JS 模块（太小或像 HTML 错误页），拒绝提供。`);
      continue;
    }
    assets.set("/vendor/" + name, { body, type: "text/javascript; charset=utf-8" });
    present.push(name); info.push(`本地算法库 vendor/${name}  ${body.length} 字节  sha256=${sha}`);
  }
  const allowCdn = present.length !== VENDOR_FILES.length;
  if (allowCdn) {
    warnings.push(`本地算法库不齐全（缺 ${missing.join(", ") || "完整性校验未通过的文件"}），CSP 仍放行 https://esm.sh：运行时代码来自第三方 CDN。建议执行 npm run vendor 固定到本地。`);
  } else {
    info.push("本地算法库齐全：CSP 已移除 https://esm.sh，运行时不再加载任何第三方代码。");
  }
  const csp = buildCsp({ scriptHashes: hashes, allowCdn });
  return { errors, warnings, info, assets, csp, hashes, allowCdn };
}

export function securityHeaders(req, { csp, trustProxy = false, nativeTls = false } = {}) {
  const overTls = nativeTls || (trustProxy && /^https$/i.test(String(req.headers["x-forwarded-proto"] || "").split(",")[0].trim()));
  const h = {
    "content-security-policy": csp,
    "x-frame-options": "DENY",
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
    "cross-origin-opener-policy": "same-origin",
    "cross-origin-resource-policy": "same-origin",
    "x-permitted-cross-domain-policies": "none",
    "permissions-policy":
      // 语音通话需要：仅向本源开放 microphone 与 autoplay；其余强能力 API 一律锁死。
      "accelerometer=(), autoplay=(self), camera=(), display-capture=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(self), payment=(), usb=()",
  };
  if (overTls) h["strict-transport-security"] = "max-age=31536000; includeSubDomains";
  return h;
}

export function makeStaticHandler({ assets, csp, trustProxy = false, nativeTls = false }) {
  return function serveStatic(req, res) {
    const sec = securityHeaders(req, { csp, trustProxy, nativeTls });
    const method = req.method || "GET";
    if (method !== "GET" && method !== "HEAD") {
      res.writeHead(405, { allow: "GET, HEAD", "content-length": 0, ...sec }); res.end(); return;
    }
    const p = (req.url || "/").split("?")[0];
    const asset = assets.get(p);
    if (!asset) {
      const body = "not found";
      res.writeHead(404, { "content-type": "text/plain; charset=utf-8", "content-length": Buffer.byteLength(body), ...sec });
      res.end(method === "HEAD" ? undefined : body); return;
    }
    res.writeHead(200, {
      "content-type": asset.type,
      "content-length": asset.body.length,
      "cache-control": "no-store",
      ...sec,
    });
    res.end(method === "HEAD" ? undefined : asset.body);
  };
}

/* ---------------------------------------------------------------------------
 * 启动 / 自检（仅当直接运行本文件时；import 时不启动，便于测试纯逻辑）。
 * ------------------------------------------------------------------------- */
function isLoopback(host) { return /^(127\.|::1$|localhost$)/.test(String(host)); }

export function runCheck(cfg = readConfig(), { log = console } = {}) {
  const prep = prepareAssets({ vendorDir: cfg.VENDOR_DIR });
  for (const s of prep.info) log.log("[信息] " + s);
  for (const s of prep.warnings) log.warn("[警告] " + s);
  for (const s of prep.errors) log.error("[错误] " + s);
  log.log("[信息] 响应头 CSP = " + prep.csp);
  const nativeTls = !!(cfg.TLS_CERT && cfg.TLS_KEY);
  if (!nativeTls && !cfg.TRUST_PROXY && !isLoopback(cfg.HOST)) {
    log.warn("[警告] 以纯 HTTP 监听非回环地址且未设置 TRUST_PROXY：浏览器在 http:// 下不提供 Web Crypto 与麦克风，本页无法工作；" +
      "请用 TLS_CERT/TLS_KEY 开启原生 TLS，或置于 TLS 反向代理之后并设置 TRUST_PROXY=1。");
  }
  if (cfg.ALLOWED_ORIGINS.includes("*")) log.warn("[警告] ALLOWED_ORIGINS=*：任何网站的页面都可以在用户浏览器里连接本中继。");
  return { ok: prep.errors.length === 0, prep };
}

async function startServer(cfg = readConfig()) {
  const { WebSocketServer } = await import("ws");             // 仅运行时需要
  const { ok, prep } = runCheck(cfg);
  if (!ok) { console.error("启动中止：请先修复上面的 [错误]。"); process.exit(1); }

  const nativeTls = !!(cfg.TLS_CERT && cfg.TLS_KEY);
  const handler = makeStaticHandler({ assets: prep.assets, csp: prep.csp, trustProxy: cfg.TRUST_PROXY, nativeTls });
  const serverOpts = { maxHeaderSize: 16 * 1024 };
  const server = nativeTls
    ? https.createServer({ ...serverOpts, cert: fs.readFileSync(cfg.TLS_CERT), key: fs.readFileSync(cfg.TLS_KEY), minVersion: "TLSv1.2" }, handler)
    : http.createServer(serverOpts, handler);
  server.headersTimeout = 15000;
  server.requestTimeout = 30000;
  server.keepAliveTimeout = 5000;
  server.maxHeadersCount = 100;
  server.on("clientError", (_err, socket) => { try { socket.destroy(); } catch {} });

  const hub = makeHub({ maxRoom: cfg.MAX_ROOM, bpHigh: cfg.BP_HIGH, bpLow: cfg.BP_LOW });
  const wss = new WebSocketServer({
    noServer: true,                 // 准入检查在 upgrade 阶段完成，握手前就拒绝
    maxPayload: cfg.MAX_PAYLOAD,
    perMessageDeflate: false,       // 密文不可压缩；避免 zlib 内存放大与压缩侧信道
    clientTracking: true,
  });
  wss.on("error", () => {});
  wss.on("connection", makeConnectionHandler({ hub, cfg }));

  const originAllowed = makeOriginPolicy(cfg.ALLOWED_ORIGINS, { trustProxy: cfg.TRUST_PROXY });
  const ipConns = new Map();
  server.on("upgrade", (req, socket, head) => {
    const deny = (code, text) => {
      try { socket.write(`HTTP/1.1 ${code} ${text}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n`); } catch {}
      try { socket.destroy(); } catch {}
    };
    if (!originAllowed(req)) return deny(403, "Forbidden");
    if (cfg.MAX_CONN > 0 && wss.clients.size >= cfg.MAX_CONN) return deny(503, "Service Unavailable");
    if (cfg.MAX_CONN_IP > 0) {
      const ip = clientIp(req, cfg.TRUST_PROXY);
      const n = ipConns.get(ip) || 0;
      if (n >= cfg.MAX_CONN_IP) return deny(429, "Too Many Requests");
      ipConns.set(ip, n + 1);
      socket.once("close", () => {                    // 无论握手成败，原始 socket 关闭即回收计数
        const m = (ipConns.get(ip) || 1) - 1;
        if (m <= 0) ipConns.delete(ip); else ipConns.set(ip, m);
      });
    }
    wss.handleUpgrade(req, socket, head, (ws) => wss.emit("connection", ws, req));
  });

  if (cfg.HEARTBEAT_MS > 0) {
    const iv = setInterval(() => heartbeatSweep(wss.clients, { stallMs: cfg.BP_STALL_MS }), cfg.HEARTBEAT_MS);
    wss.on("close", () => clearInterval(iv));
  }

  const shutdown = () => {
    for (const c of wss.clients) { try { c.close(1001, "server shutdown"); } catch {} }
    wss.close(); server.close(() => process.exit(0));
    setTimeout(() => process.exit(0), 3000).unref();
  };
  process.once("SIGTERM", shutdown); process.once("SIGINT", shutdown);

  server.listen(cfg.PORT, cfg.HOST, () => {
    const scheme = nativeTls ? "https" : "http";
    const originDesc = cfg.ALLOWED_ORIGINS.includes("*") ? "任意（已显式放开）"
      : cfg.ALLOWED_ORIGINS.length ? `同源 + ${cfg.ALLOWED_ORIGINS.join("|")}` : "仅同源（默认；跨站页面连接请设 ALLOWED_ORIGINS）";
    console.log(
      `pqsession 中继 v2 已启动 → ${scheme}://${cfg.HOST}:${cfg.PORT}\n` +
      `  单帧上限 ${(cfg.MAX_PAYLOAD / 1048576).toFixed(0)} MiB · 消息限流 ${cfg.MSG_RATE}/s · 字节整形 ${cfg.BYTES_RATE ? (cfg.BYTES_RATE / 1048576).toFixed(0) + " MiB/s" : "关闭"}\n` +
      `  背压 高/低水位 ${(cfg.BP_HIGH / 1048576).toFixed(0)}/${(cfg.BP_LOW / 1048576).toFixed(0)} MiB · 僵死判定 ${cfg.BP_STALL_MS} ms · 心跳 ${cfg.HEARTBEAT_MS} ms\n` +
      `  每 IP 连接上限 ${cfg.MAX_CONN_IP || "不限"} · 全局上限 ${cfg.MAX_CONN || "不限"} · 未入房清理 ${cfg.JOIN_TIMEOUT_MS} ms\n` +
      `  Origin 策略 ${originDesc} · TRUST_PROXY ${cfg.TRUST_PROXY ? "开" : "关"} · 算法库 ${prep.allowCdn ? "esm.sh（未固定）" : "本地 vendor/"}\n` +
      `  中继不记录任何每连接日志（元数据最小化）。`);
  });
}

const isMain = import.meta.url === url.pathToFileURL(process.argv[1] || "").href;
if (isMain) {
  if (process.argv.includes("--check")) process.exit(runCheck().ok ? 0 : 1);
  await startServer();
}
