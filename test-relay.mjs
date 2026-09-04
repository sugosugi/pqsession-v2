// 中继纯逻辑测试：不需要安装 ws，也不需要联网。  运行：npm test
import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import {
  makeHub, makeRateLimiter, makeByteShaper, heartbeatSweep, makeOriginPolicy,
  makeConnectionHandler, inlineScriptHashes, metaCspOf, buildCsp, prepareAssets,
  makeStaticHandler, readConfig, ROOT, HTML_FILE, VENDOR_FILES,
} from "./server.js";

let passed = 0;
function test(name, fn) { fn(); passed++; console.log("  ✓ " + name); }

// 假客户端：模仿 ws 8 的 WebSocket 对象（send/pause/resume/bufferedAmount/ping/terminate）
class FakeWs extends EventEmitter {
  constructor(name) {
    super(); this.name = name; this.out = []; this.paused = false; this.bufferedAmount = 0;
    this.pending = []; this.closed = null; this.terminated = false; this.pinged = 0; this.room = null;
  }
  send(s, cb) { this.out.push(JSON.parse(s)); if (cb) this.pending.push(cb); }
  flushOne() { const cb = this.pending.shift(); if (cb) cb(); }
  flush() { while (this.pending.length) this.flushOne(); }
  pause() { this.paused = true; }
  resume() { this.paused = false; }
  ping() { this.pinged++; }
  terminate() { this.terminated = true; this.emit("close"); }
  close(code, reason) { this.closed = { code, reason }; this.emit("close"); }
  sigs() { return this.out.filter((m) => m.t === "sig").map((m) => m.d); }
}

console.log("makeHub / 背压");
test("join + relay：只转发给另一端，d 原样不动", () => {
  const hub = makeHub();
  const a = new FakeWs("a"), b = new FakeWs("b");
  assert.equal(hub.join(a, "r").n, 1);
  assert.equal(hub.join(b, "r").n, 2);
  assert.deepEqual(a.out[0], { t: "peer", event: "join", n: 2 });
  const d = { v: 2, n: "AAAA", c: "BBBB", nested: { x: [1, 2, { y: null }] } };
  assert.equal(hub.relay(a, d), 1);
  assert.deepEqual(b.sigs(), [d]);
  assert.equal(a.sigs().length, 0);
  const c = new FakeWs("c");
  assert.deepEqual(hub.join(c, "r"), { ok: false, reason: "full" });
  assert.deepEqual(hub.join(c, 42), { ok: false, reason: "bad-room" });
  hub.leave(a);
  assert.deepEqual(b.out.at(-1), { t: "peer", event: "leave", n: 1 });
  assert.equal(hub.relay(a, d), 0, "离开房间后不再转发");
});

test("背压：对端缓冲过高 → 暂停来源；排空回调后 → 恢复", () => {
  let t = 1000;
  const hub = makeHub({ bpHigh: 100, bpLow: 10, now: () => t });
  const a = new FakeWs("a"), b = new FakeWs("b");
  hub.join(a, "r"); hub.join(b, "r");
  b.bufferedAmount = 500;                      // b 读得慢
  hub.relay(a, "x"); hub.relay(a, "x2");       // 第二帧模拟“暂停前已在途”的帧
  assert.equal(a.paused, true, "来源 a 应被暂停");
  assert.equal(a.bpWaitOn, b);
  assert.equal(a.bpSince, 1000);
  b.bufferedAmount = 50; b.flushOne();         // 第一帧写出，仍高于低水位：不恢复
  assert.equal(a.paused, true);
  b.bufferedAmount = 0; b.flushOne();          // 最后一帧写出，缓冲清空：恢复
  assert.equal(a.paused, false, "低于低水位后应恢复");
  assert.equal(a.bpWaitOn, null);
  // 暂停期间心跳不得误杀（读不到 pong）
  b.bufferedAmount = 1000; hub.relay(a, "x3");
  a.isAlive = false;
  assert.deepEqual(heartbeatSweep([a], { now: 2000, stallMs: 0 }), { pinged: 0, killed: 0 });
  assert.equal(a.terminated, false);
});

test("背压：对端离开时来源自动恢复；多原因 hold 全部解除才恢复", () => {
  const hub = makeHub({ bpHigh: 100, bpLow: 10 });
  const a = new FakeWs("a"), b = new FakeWs("b");
  hub.join(a, "r"); hub.join(b, "r");
  b.bufferedAmount = 1000; hub.relay(a, "x");
  hub.hold(a, "shape");
  hub.leave(b);
  assert.equal(a.paused, true, "shape 仍在，不应恢复");
  hub.release(a, "shape");
  assert.equal(a.paused, false);
});

test("心跳：未回 pong 的终止；被背压拖住超时的对端被判僵死终止", () => {
  const hub = makeHub({ bpHigh: 100, bpLow: 10, now: () => 0 });
  const a = new FakeWs("a"), b = new FakeWs("b"), c = new FakeWs("c");
  hub.join(a, "r"); hub.join(b, "r"); hub.join(c, "other");
  b.bufferedAmount = 1000; hub.relay(a, "x");
  a.isAlive = true; b.isAlive = true; c.isAlive = false;
  const r1 = heartbeatSweep([a, b, c], { now: 30000, stallMs: 60000 });
  assert.deepEqual(r1, { pinged: 1, killed: 1, stalled: 0 }, "被暂停的 a 不参与 ping");
  assert.equal(c.terminated, true);
  a.isAlive = true; b.isAlive = true;
  const r2 = heartbeatSweep([a, b], { now: 61000, stallMs: 60000 });
  assert.equal(r2.stalled, 1);
  assert.equal(b.terminated, true, "不读数据的 b 被踢");
  assert.equal(a.terminated, false);
  // b 的 close 已触发 hub.leave(b)？（真实 ws 里由 connection handler 完成；这里手动）
  hub.leave(b);
  assert.equal(a.paused, false, "b 走后 a 恢复");
  assert.deepEqual(heartbeatSweep([a]), { pinged: 1, killed: 0 }, "旧签名与返回值形状仍兼容");
});

console.log("限流 / 整形");
test("消息令牌桶：突发后拒绝，随时间恢复", () => {
  const rl = makeRateLimiter({ ratePerSec: 10, burst: 3 });
  const t0 = 1000;
  assert.equal(rl.take(t0), true); assert.equal(rl.take(t0), true); assert.equal(rl.take(t0), true);
  assert.equal(rl.take(t0), false);
  assert.equal(rl.take(t0 + 100), true);       // 0.1s 补 1 个
  assert.equal(rl.take(t0 + 100), false);
});
test("字节整形：不丢帧，返回需暂停的毫秒数；0 速率=关闭", () => {
  const sh = makeByteShaper({ bytesPerSec: 1000, burst: 2000 });
  const t0 = 5000;
  assert.equal(sh.consume(1500, t0), 0);
  assert.equal(sh.consume(1500, t0), 1000);     // 透支 1000 字节 → 等 1000ms
  assert.equal(sh.consume(0, t0 + 1000), 0);    // 补回来了
  assert.equal(makeByteShaper({ bytesPerSec: 0, burst: 0 }).consume(1e9), 0);
});

console.log("Origin 策略");
test("默认仅同源；列表；* 放行；缺 Origin / null / 非 http 拒绝", () => {
  const same = makeOriginPolicy([]);
  assert.equal(same({ headers: { origin: "https://chat.example.com", host: "chat.example.com" } }), true);
  assert.equal(same({ headers: { origin: "https://CHAT.example.com:443", host: "chat.example.com" } }), true);
  assert.equal(same({ headers: { origin: "http://localhost:8080", host: "localhost:8080" } }), true);
  assert.equal(same({ headers: { origin: "https://evil.example", host: "chat.example.com" } }), false);
  assert.equal(same({ headers: { host: "chat.example.com" } }), false);
  assert.equal(same({ headers: { origin: "null", host: "chat.example.com" } }), false);
  assert.equal(same({ headers: { origin: "file:///x", host: "chat.example.com" } }), false);
  const listed = makeOriginPolicy(["https://Front.example/"]);
  assert.equal(listed({ headers: { origin: "https://front.example", host: "relay.example" } }), true);
  assert.equal(listed({ headers: { origin: "https://relay.example", host: "relay.example" } }), true, "列表模式仍允许同源");
  assert.equal(listed({ headers: { origin: "https://other.example", host: "relay.example" } }), false);
  const any = makeOriginPolicy(["*"]);
  assert.equal(any({ headers: {} }), true);
  const proxied = makeOriginPolicy([], { trustProxy: true });
  assert.equal(proxied({ headers: { origin: "https://pub.example", host: "10.0.0.5:8080", "x-forwarded-host": "pub.example" } }), true);
});

console.log("连接处理（v1 崩溃点回归）");
function wire(cfgOverride = {}) {
  const timers = [];
  const cfg = { ...readConfig({}), ...cfgOverride };
  const hub = makeHub({ bpHigh: cfg.BP_HIGH, bpLow: cfg.BP_LOW });
  const onConn = makeConnectionHandler({
    hub, cfg, now: () => 1e6,
    setTimer: (fn, ms) => { const h = { fn, ms, cleared: false }; timers.push(h); return h; },
    clearTimer: (h) => { h.cleared = true; },
  });
  return { hub, onConn, timers };
}
test("JSON null / 数组 / 标量 / 垃圾 / 二进制帧：全部静默丢弃，不抛异常", () => {
  const { onConn } = wire();
  const ws = new FakeWs("x"); onConn(ws);
  for (const raw of ["null", "true", "1", "\"s\"", "[1,2]", "{", "", "{\"t\":\"sig\"}", "{\"t\":\"join\"}", "{\"t\":\"join\",\"room\":5}"]) {
    ws.emit("message", Buffer.from(raw), false);
  }
  ws.emit("message", Buffer.from([1, 2, 3]), true);
  assert.equal(ws.out.length, 0);
});
test("正常流程：join → joined；sig 转发；离开清理；未入房间的 sig 不转发", () => {
  const { hub, onConn } = wire();
  const a = new FakeWs("a"), b = new FakeWs("b"); onConn(a); onConn(b);
  a.emit("message", Buffer.from(JSON.stringify({ t: "join", room: "R" })), false);
  assert.deepEqual(a.out[0], { t: "joined", n: 1 });
  b.emit("message", Buffer.from(JSON.stringify({ t: "sig", d: "early" })), false);
  assert.equal(a.sigs().length, 0, "b 未入房间，不能转发");
  b.emit("message", Buffer.from(JSON.stringify({ t: "join", room: "R" })), false);
  assert.deepEqual(b.out.at(-1), { t: "joined", n: 2 });
  b.emit("message", Buffer.from(JSON.stringify({ t: "sig", d: { v: 2 } })), false);
  assert.deepEqual(a.sigs(), [{ v: 2 }]);
  const c = new FakeWs("c"); onConn(c);
  c.emit("message", Buffer.from(JSON.stringify({ t: "join", room: "R" })), false);
  assert.deepEqual(c.out[0], { t: "full" });
  b.emit("close");
  assert.deepEqual(a.out.at(-1), { t: "peer", event: "leave", n: 1 });
  assert.equal(hub.rooms.get("R").size, 1);
});
test("入房超时：迟迟不 join 的连接被关闭；已入房的不会", () => {
  const { onConn, timers } = wire({ JOIN_TIMEOUT_MS: 5000 });
  const a = new FakeWs("a"), b = new FakeWs("b"); onConn(a); onConn(b);
  b.emit("message", Buffer.from(JSON.stringify({ t: "join", room: "R" })), false);
  for (const h of timers) if (!h.cleared) h.fn();
  assert.deepEqual(a.closed, { code: 1008, reason: "join timeout" });
  assert.equal(b.closed, null);
});
test("字节整形：超额时暂停读取而不是丢帧，定时器到期恢复", () => {
  const { onConn, timers } = wire({ BYTES_RATE: 1000, BYTES_BURST: 1000 });
  const a = new FakeWs("a"), b = new FakeWs("b"); onConn(a); onConn(b);
  for (const w of [a, b]) w.emit("message", Buffer.from(JSON.stringify({ t: "join", room: "R" })), false);
  const big = JSON.stringify({ t: "sig", d: "x".repeat(3000) });
  a.emit("message", Buffer.from(big), false);
  assert.equal(b.sigs().length, 1, "帧仍被转发");
  assert.equal(a.paused, true, "但来源被暂停");
  const shape = timers.find((h) => h.ms > 0 && h.ms < 5000 && !h.cleared);
  assert.ok(shape, "存在整形定时器"); shape.fn();
  assert.equal(a.paused, false);
});

console.log("CSP / 静态资源");
const html = fs.readFileSync(path.join(ROOT, HTML_FILE), "utf8");
test("内联脚本哈希与页内 <meta> 一致，且 meta 无 unsafe-inline 脚本", () => {
  const hashes = inlineScriptHashes(html);
  assert.equal(hashes.length, 1);
  const meta = metaCspOf(html);
  assert.ok(meta && meta.includes(hashes[0]), "meta 必须包含 " + hashes[0]);
  assert.ok(!/script-src[^;]*unsafe-inline/.test(meta));
  assert.ok(!/fonts\.googleapis|fonts\.gstatic/.test(html), "不应再引用第三方字体");
});
test("prepareAssets：无 vendor 时放行 esm.sh；vendor 齐全时移除；伪造的 vendor（HTML 错误页）被拒", () => {
  const p1 = prepareAssets({ vendorDir: path.join(os.tmpdir(), "pq-none-" + Date.now()) });
  assert.deepEqual(p1.errors, []);
  assert.equal(p1.allowCdn, true);
  assert.ok(p1.csp.includes("https://esm.sh"));
  assert.ok(p1.csp.includes("frame-ancestors 'none'"));
  assert.ok(p1.assets.has("/") && p1.assets.has("/" + HTML_FILE));
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "pq-vendor-"));
  for (const f of VENDOR_FILES) fs.writeFileSync(path.join(dir, f), "export const ok=1;\n" + "// pad\n".repeat(300));
  const p2 = prepareAssets({ vendorDir: dir });
  assert.deepEqual(p2.errors, []);
  assert.equal(p2.allowCdn, false);
  assert.ok(!p2.csp.includes("esm.sh"));
  assert.ok(p2.csp.includes("'self'"));
  for (const f of VENDOR_FILES) assert.ok(p2.assets.has("/vendor/" + f));
  fs.writeFileSync(path.join(dir, VENDOR_FILES[0]), "<html>Not Found</html>" + " ".repeat(2000));
  const p3 = prepareAssets({ vendorDir: dir });
  assert.equal(p3.errors.length, 1);
  assert.equal(p3.allowCdn, true);
});
test("<meta> 哈希失配或 script-src 含 unsafe-inline 时 prepareAssets 报错（服务器拒绝启动）", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "pq-html-"));
  fs.writeFileSync(path.join(dir, HTML_FILE), html.replace("</script>", "\n// tampered\n</script>"));
  const bad = prepareAssets({ root: dir, vendorDir: "/nonexistent" });
  assert.equal(bad.errors.length, 1); assert.match(bad.errors[0], /未包含内联脚本的当前哈希/);
  const cur = metaCspOf(html);
  fs.writeFileSync(path.join(dir, HTML_FILE), html.replace(cur, cur.replace("script-src ", "script-src 'unsafe-inline' ")));
  const bad2 = prepareAssets({ root: dir, vendorDir: "/nonexistent" });
  assert.ok(bad2.errors.some((e) => /unsafe-inline/.test(e)));
  const good = prepareAssets({ root: dir.replace(/.*/, ROOT), vendorDir: "/nonexistent" });
  assert.deepEqual(good.errors, []);
});
test("buildCsp 形状", () => {
  const c = buildCsp({ scriptHashes: ["sha256-abc"], allowCdn: false });
  assert.ok(c.startsWith("default-src 'none'; script-src 'self' 'wasm-unsafe-eval' blob: 'sha256-abc'; "));
});
test("静态处理：GET/HEAD 正常，其他方法 405，未知路径 404，带全部安全头", () => {
  const prep = prepareAssets({ vendorDir: "/nonexistent" });
  const h = makeStaticHandler({ assets: prep.assets, csp: prep.csp, trustProxy: true });
  function run(method, u, headers = {}) {
    let head = null, body = "";
    const res = { writeHead: (s, hs) => { head = { s, hs }; }, end: (b) => { body = b ? b.toString() : ""; } };
    h({ method, url: u, headers }, res); return { ...head, body };
  }
  const r = run("GET", "/?x=1");
  assert.equal(r.s, 200); assert.ok(r.body.startsWith("<!doctype html>"));
  for (const k of ["content-security-policy", "x-frame-options", "x-content-type-options", "referrer-policy", "cross-origin-opener-policy", "permissions-policy", "cache-control"]) assert.ok(r.hs[k], "缺响应头 " + k);
  // 语音通话依赖这两条：收紧成 microphone=() 会让浏览器静默拒绝且不弹权限窗
  assert.match(r.hs["permissions-policy"], /microphone=\(self\)/);
  assert.match(r.hs["permissions-policy"], /autoplay=\(self\)/);
  assert.match(r.hs["permissions-policy"], /camera=\(\)/);
  assert.equal(r.hs["strict-transport-security"], undefined);
  assert.ok(run("GET", "/", { "x-forwarded-proto": "https" }).hs["strict-transport-security"]);
  const hd = run("HEAD", "/pqsession-net.html"); assert.equal(hd.s, 200); assert.equal(hd.body, "");
  assert.equal(run("POST", "/").s, 405);
  assert.equal(run("GET", "/../etc/passwd").s, 404);
  assert.equal(run("GET", "/vendor/ml-kem.mjs").s, 404);
});

console.log(`\n全部通过：${passed} 项。`);

// 若作者原有的 test-hub.mjs 仍在，顺带跑一遍（保持向后兼容）
const legacy = path.join(ROOT, "test-hub.mjs");
if (fs.existsSync(legacy)) {
  console.log("\n运行 test-hub.mjs …");
  const r = spawnSync(process.execPath, [legacy], { stdio: "inherit" });
  if (r.status !== 0) process.exit(r.status || 1);
}
