// 语音通话端到端测试（Node 内跑，不需要浏览器、不需要 ws、不联网）：
// 把 pqsession-net.html 里的整段页面脚本作为函数体载入两份（A / B），注入假 DOM、假 WebSocket（内存中继，
// 严格保序、可加延迟/抖动）、假 Web Audio（真的执行页内 AudioWorklet 源码；也模拟没有 AudioWorklet 的浏览器），
// 用假 KEM / 假 Argon2 走完真实握手，然后驱动一次完整通话并检查对端听到的音频频率。运行：node test-voice.mjs
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";

const ROOT = path.dirname(fileURLToPath(import.meta.url));
const html = fs.readFileSync(path.join(ROOT, "pqsession-net.html"), "utf8");
let src = html.match(/<script type="module">([\s\S]*?)<\/script>/)[1];
assert.ok(src.includes("let nobleKem = null;") && src.includes("let hw = null;"), "找不到算法库注入点");
src = src.replace("let nobleKem = null;", "let nobleKem = __fakeKem;").replace("let hw = null;", "let hw = __fakeHw;");
src += "\n;__expose({ getCall:()=>call, getSession:()=>session, getWs:()=>ws, getId:()=>myIdentity });\n";

process.on("unhandledRejection", (e) => { console.error("  ✗ 未处理的 Promise 拒绝：", e); process.exit(1); });

/* ---- 尺寸忠实的假 KEM / 假 Argon2（只验证协议与通话逻辑；不是密码学安全实现） ---- */
const PK = 1568, SK = 3168, CT = 1568;
const sha = (...bs) => new Uint8Array(crypto.createHash("sha256").update(Buffer.concat(bs.map((b) => Buffer.from(b)))).digest());
const fakeKem = {
  keygen() { const seed = crypto.randomBytes(32); const pk = new Uint8Array(PK); pk.set(sha(seed), 0); const sk = new Uint8Array(SK); sk.set(seed, 0); return { publicKey: pk, secretKey: sk }; },
  encapsulate(pk) { const r = crypto.randomBytes(32); const ct = new Uint8Array(CT); ct.set(r, 0); return { cipherText: ct, sharedSecret: sha(pk.subarray(0, 32), r) }; },
  decapsulate(ct, sk) { return sha(sha(sk.subarray(0, 32)), ct.subarray(0, 32)); },
};
const fakeHw = { async argon2id({ password, salt, hashLength }) {
  const k = await globalThis.crypto.subtle.importKey("raw", password, "PBKDF2", false, ["deriveBits"]);
  return new Uint8Array(await globalThis.crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt, iterations: 100 }, k, hashLength * 8));
} };

/* ---- 内存中继：与 server.js 的 join / joined / peer / sig 帧一致；每个方向严格保序 ---- */
const NET = { latency: 1, jitter: 0 };
const hub = { rooms: new Map(), members: new Map(),
  join(ws, room) { let set = this.rooms.get(room); if (!set) { set = new Set(); this.rooms.set(room, set); }
    if (set.size >= 2) return { ok: false }; set.add(ws); this.members.set(ws, room);
    for (const p of set) if (p !== ws) deliver(p, { t: "peer", event: "join", n: set.size }); return { ok: true, n: set.size }; },
  leave(ws) { const room = this.members.get(ws); if (!room) return; const set = this.rooms.get(room); set.delete(ws); this.members.delete(ws);
    for (const p of set) deliver(p, { t: "peer", event: "leave", n: set.size }); },
  sig(ws, d) { const room = this.members.get(ws); if (!room) return; for (const p of this.rooms.get(room)) if (p !== ws) deliver(p, { t: "sig", d }); },
};
const queues = new Map();
function deliver(ws, obj) {
  const s = JSON.stringify(obj); let q = queues.get(ws); if (!q) { q = { items: [], timer: null, last: 0 }; queues.set(ws, q); }
  const at = Math.max(q.last, Date.now() + NET.latency + Math.random() * NET.jitter); q.last = at; q.items.push({ s, at }); if (!q.timer) pump(ws, q);
}
function pump(ws, q) {
  if (!q.items.length) { q.timer = null; return; }
  const head = q.items[0];
  q.timer = setTimeout(() => { q.items.shift(); if (ws.readyState === 1 && ws.onmessage) ws.onmessage({ data: head.s }); pump(ws, q); }, Math.max(0, head.at - Date.now()));
}
class FakeWS {
  constructor(url) { this.url = url; this.readyState = 0; this.bufferedAmount = 0; this.onopen = this.onclose = this.onerror = this.onmessage = null; setTimeout(() => { this.readyState = 1; this.onopen && this.onopen(); }, 1); }
  send(s) { if (this.readyState !== 1) throw new Error("ws not open"); const m = JSON.parse(s);
    if (m.t === "join") { const r = hub.join(this, m.room); deliver(this, r.ok ? { t: "joined", n: r.n } : { t: "full" }); return; }
    if (m.t === "sig") hub.sig(this, m.d); }
  close() { if (this.readyState === 3) return; this.readyState = 3; hub.leave(this); setTimeout(() => this.onclose && this.onclose(), 1); }
}

/* ---- 假 Web Audio：MessagePort 用 structuredClone(transfer) 真正分离缓冲区；页内 Worklet 源码被真的执行 ---- */
const FLAGS = { noWorklet: false, failAddModule: false, micRate: 0, ctxRate: 48000 };
let currentPort = null;
class FakeProcessorBase { constructor() { this.port = currentPort; } }
class FakeAudioWorkletNode {
  constructor(ctx, name, opts) {
    if (ctx.state === "closed") throw new Error("InvalidStateError: context closed");
    const P = ctx.registry.get(name); if (!P) throw new Error("InvalidStateError: processor not registered: " + name);
    const xfer = (d, tr) => structuredClone(d, tr ? { transfer: tr } : undefined);
    const nodePort = { onmessage: null, postMessage: (d, tr) => { const c = xfer(d, tr); queueMicrotask(() => procPort.onmessage && procPort.onmessage({ data: c })); } };
    const procPort = { onmessage: null, postMessage: (d, tr) => { const c = xfer(d, tr); queueMicrotask(() => nodePort.onmessage && nodePort.onmessage({ data: c })); } };
    currentPort = procPort; this.proc = new P(opts); currentPort = null;
    this.port = nodePort; this.name = name; ctx.nodes.push(this);
  }
  connect(n) { return n; } disconnect() {}
}
const blobs = new Map();
const FakeURL = Object.assign(function (...a) { return new URL(...a); }, {
  createObjectURL(b) { const u = "blob:fake/" + crypto.randomUUID(); blobs.set(u, b); return u; },
  revokeObjectURL(u) { blobs.delete(u); },
});
FakeURL.prototype = URL.prototype;
class FakeAudioContext {
  constructor(list) { this._sr = FLAGS.ctxRate; this._state = "suspended"; this.onstatechange = null; this.registry = new Map(); this.nodes = []; this.sp = []; this.destination = { connect() {}, disconnect() {} };
    const self = this;
    if (!FLAGS.noWorklet) this.audioWorklet = { async addModule(url) {
      if (FLAGS.failAddModule) { const e = new Error("Unable to load a worklet's module."); e.name = "AbortError"; throw e; }
      const blob = blobs.get(url); if (!blob) throw new Error("addModule: unknown url " + url);
      new Function("AudioWorkletProcessor", "registerProcessor", "sampleRate", await blob.text())(FakeProcessorBase, (n, c) => self.registry.set(n, c), self.sampleRate); } };
    list.push(this);
  }
  get sampleRate() { return this._sr; }
  get state() { return this._state; }
  set state(v) { if (this._state !== v) { this._state = v; if (this.onstatechange) queueMicrotask(() => this.onstatechange && this.onstatechange()); } }
  async resume() { if (this._state === "closed") throw new Error("InvalidStateError"); this.state = "running"; }
  async close() { if (this._state === "closed") throw new Error("InvalidStateError: already closed"); this.state = "closed"; }
  createMediaStreamSource(stream) { if (this._state === "closed") throw new Error("InvalidStateError"); return { stream, connect() {}, disconnect() {} }; }
  createGain() { return { gain: { value: 1 }, connect() {}, disconnect() {} }; }
  createScriptProcessor(bufferSize, inCh, outCh) { const n = { bufferSize, inCh, outCh, onaudioprocess: null, connect() {}, disconnect() {} }; this.sp.push(n); return n; }
}

/* ---- 假 DOM：按 id 懒创建元素；log 面板的每一行都被记下 ---- */
function makeDoc() {
  const doc = { els: new Map(), logLines: [] };
  function makeEl(tagName) {
    return { tagName, id: "", className: "", _text: "", innerHTML: "", value: "", checked: false, disabled: false, style: { cssText: "" }, dataset: {}, children: [], _l: {}, scrollTop: 0, scrollHeight: 0, onclick: null, onkeydown: null,
      get textContent() { return this._text; }, set textContent(v) { this._text = String(v); this.children = []; },
      classList: { _s: new Set(), add(...c) { c.forEach((x) => this._s.add(x)); }, remove(...c) { c.forEach((x) => this._s.delete(x)); }, toggle(c, f) { if (f === undefined) f = !this._s.has(c); f ? this._s.add(c) : this._s.delete(c); return f; }, contains(c) { return this._s.has(c); } },
      addEventListener(ev, fn) { (this._l[ev] ||= []).push(fn); },
      async dispatch(ev, arg) { for (const fn of (this._l[ev] || [])) await fn(arg || { target: this, preventDefault() {}, key: "" }); },
      appendChild(c) { this.children.push(c); if (this.id === "log") doc.logLines.push(c.textContent); return c; },
      querySelector(sel) { const cls = sel.replace(/^\./, ""); return this.children.find((c) => String(c.className).split(" ").includes(cls)) || null; },
      querySelectorAll() { return []; }, setAttribute() {}, focus() {}, select() {}, remove() {}, click() { return this.dispatch("click"); },
    };
  }
  doc.getElementById = (id) => { let e = doc.els.get(id); if (!e) { e = makeEl("div"); e.id = id; doc.els.set(id, e); } return e; };
  doc.createElement = (t) => makeEl(t); doc.querySelectorAll = () => []; doc.body = makeEl("body");
  return doc;
}

/* ---- 载入一份页面 ---- */
const PARAMS = ["window", "document", "navigator", "location", "localStorage", "WebSocket", "AudioWorkletNode", "URL", "confirm", "alert", "prompt", "FileReader", "__fakeKem", "__fakeHw", "__expose"];
const pageFn = new Function(...PARAMS, src);
function makePeer(tag) {
  const document = makeDoc();
  const ls = { m: new Map(), getItem(k) { return this.m.has(k) ? this.m.get(k) : null; }, setItem(k, v) { this.m.set(k, String(v)); }, removeItem(k) { this.m.delete(k); } };
  const contexts = [], tracks = [];
  class PeerAudioContext extends FakeAudioContext { constructor() { super(contexts); } }
  const window = { crypto: globalThis.crypto, isSecureContext: true, localStorage: ls, AudioContext: PeerAudioContext, prompt() { return null; }, addEventListener() {} };
  const makeStream = () => { const track = { kind: "audio", label: "Fake Mic", readyState: "live", onended: null, stop() { this.readyState = "ended"; }, getSettings() { return { sampleRate: FLAGS.micRate || FLAGS.ctxRate, echoCancellation: true, channelCount: 1 }; } };
    tracks.push(track); return { getTracks() { return [track]; }, getAudioTracks() { return [track]; } }; };
  const navigator = { mediaDevices: { getUserMedia: async () => makeStream() }, clipboard: { writeText: async () => {} } };
  let api = null;
  pageFn(window, document, navigator, { protocol: "https:", host: "relay.test", href: "https://relay.test/" }, ls, FakeWS, FakeAudioWorkletNode, FakeURL, () => true, () => {}, () => null, class {}, fakeKem, fakeHw, (o) => { api = o; });
  return { tag, document, $: document.getElementById, api, navigator, contexts, tracks, log: () => document.logLines, last: () => document.logLines[document.logLines.length - 1] || "" };
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function until(pred, what, ms = 8000) { const t0 = Date.now(); while (!pred()) { if (Date.now() - t0 > ms) throw new Error("等待超时：" + what); await sleep(4); } }
async function pair(room) {
  const A = makePeer("A"), B = makePeer("B");
  for (const p of [A, B]) { await p.$("genBtn").dispatch("click"); await until(() => p.api.getId(), p.tag + " 身份"); }
  for (const p of [A, B]) { p.$("srvUrl").value = "wss://relay.test"; p.$("roomCode").value = room; }
  await A.$("connectBtn").dispatch("click"); await B.$("connectBtn").dispatch("click");
  await until(() => A.$("peerFp").textContent && B.$("peerFp").textContent, "指纹交换");
  for (const p of [A, B]) { p.$("fpCheck").checked = true; await p.$("verifyBtn").dispatch("click"); }
  await until(() => A.api.getSession() && B.api.getSession(), "会话建立");
  return [A, B];
}
async function callAB(A, B) {
  await A.$("callBtn").dispatch("click");
  await until(() => B.api.getCall() && B.api.getCall().state === "ring-in", "B 响铃");
  await B.$("callAccept").dispatch("click");
  await until(() => A.api.getCall()?.state === "active" && B.api.getCall()?.state === "active", "双方 active");
}
// 音频图句柄：Worklet 模式取 vc-cap / vc-play 节点，兼容模式取两个 ScriptProcessor
function graphOf(p) {
  const ctxs = p.contexts.filter((c) => c.state === "running"); assert.equal(ctxs.length, 1, p.tag + " 应恰有一个运行中的 AudioContext");
  const ctx = ctxs[0];
  const cap = ctx.nodes.find((n) => n.name === "vc-cap"), play = ctx.nodes.find((n) => n.name === "vc-play");
  if (cap && play) return { mode: "worklet", rate: ctx.sampleRate,
    feed: (inp) => cap.proc.process([[inp]], [[new Float32Array(128)]]),
    pull: () => { const o = new Float32Array(128); play.proc.process([], [[o]]); return o; } };
  const [spCap, spPlay] = ctx.sp; assert.ok(spCap && spPlay, p.tag + " 兼容模式应创建两个 ScriptProcessor");
  const buf = (ch, n) => ({ numberOfChannels: ch, length: n, _d: Array.from({ length: ch }, () => new Float32Array(n)), getChannelData(i) { return this._d[i]; } });
  return { mode: "script", rate: ctx.sampleRate,
    feed: (inp) => { const ib = buf(1, inp.length); ib._d[0].set(inp); spCap.onaudioprocess({ inputBuffer: ib, outputBuffer: buf(1, inp.length) }); },
    pull: () => { const ob = buf(1, 128); spPlay.onaudioprocess({ inputBuffer: buf(1, 128), outputBuffer: ob }); return ob._d[0]; } };
}
// 驱动 seconds 秒：A 的麦克风是 fa Hz 正弦，B 的是 fb Hz；返回双方后半段听到的主频与幅度
async function talk(A, B, seconds, { fa = 440, fb = 880, driftB = 0 } = {}) {
  const gA = graphOf(A), gB = graphOf(B); const outA = [], outB = []; let tA = 0, tB = 0;
  const step = (g, f, t, out) => { const inp = new Float32Array(128); for (let i = 0; i < 128; i++) inp[i] = 0.5 * Math.sin(2 * Math.PI * f * (t + i) / g.rate); g.feed(inp); out.push(g.pull()); return t + 128; };
  const N = Math.round(seconds * gA.rate / 128);
  for (let i = 0; i < N; i++) { tA = step(gA, fa, tA, outA); if (!(driftB && i % driftB === 0)) tB = step(gB, fb, tB, outB); if (i % 4 === 0) await sleep(0); if (i % 100 === 0) await sleep(12); }
  await sleep(150);
  const measure = (arrs, rate) => { const all = []; for (let k = Math.floor(arrs.length / 2); k < arrs.length; k++) for (const v of arrs[k]) all.push(v);
    let s = 0, z = 0; for (let i = 0; i < all.length; i++) { s += all[i] * all[i]; if (i && (all[i - 1] < 0) !== (all[i] < 0)) z++; }
    return { rms: Math.sqrt(s / all.length), freq: z / 2 / (all.length / rate) }; };
  return { a: measure(outA, gA.rate), b: measure(outB, gB.rate), modeA: gA.mode, modeB: gB.mode };
}
const near = (x, y, tol) => Math.abs(x - y) <= tol;
const noRunning = (p) => p.contexts.every((c) => c.state === "closed") && p.tracks.every((t) => t.readyState === "ended");

let passed = 0;
async function test(name, fn) { await fn(); passed++; console.log("  ✓ " + name); }

console.log("语音通话");
{
  const [A, B] = await pair("ROOM-BASIC-01");
  await test("呼叫 → 响铃 → 接听 → 双方 active；AudioWorklet 模式下双向音频往返，频率正确", async () => {
    await callAB(A, B);
    const r = await talk(A, B, 2.5);
    assert.equal(r.modeA, "worklet"); assert.equal(r.modeB, "worklet");
    assert.ok(near(r.a.freq, 880, 15) && r.a.rms > 0.2, `A 听到 ${r.a.freq.toFixed(0)}Hz rms=${r.a.rms.toFixed(3)}`);
    assert.ok(near(r.b.freq, 440, 15) && r.b.rms > 0.2, `B 听到 ${r.b.freq.toFixed(0)}Hz rms=${r.b.rms.toFixed(3)}`);
    assert.ok(A.log().some((l) => /音频链路就绪：AudioWorklet/.test(l)), "应记录链路诊断");
    assert.equal(A.api.getCall().seq, B.api.getCall().seq, "恒定码率：双方包数一致");
  });
  await test("静音：对方听到的为全零，但包仍在持续发送（恒定码率）", async () => {
    const s0 = A.api.getCall().seq;
    await A.$("callMute").dispatch("click"); assert.equal(A.api.getCall().muted, true);
    const r = await talk(A, B, 0.8);
    assert.ok(r.b.rms < 1e-6, "B 应听到静音"); assert.ok(near(r.a.freq, 880, 15), "A 仍听到 B");
    assert.ok(A.api.getCall().seq > s0 + 5, "静音期间仍发包");
    await A.$("callMute").dispatch("click"); assert.equal(A.api.getCall().muted, false);
  });
  await test("通话中发文字与文件：与语音同走串行棘轮，全部送达且语音不断", async () => {
    A.$("msgIn").value = "call-text"; await A.$("sendBtn").dispatch("click");
    const bytes = new Uint8Array(150 * 1024); crypto.getRandomValues(bytes.subarray(0, 65536));
    const file = { name: "c.bin", size: bytes.length, type: "application/octet-stream", slice(a, b) { return { arrayBuffer: async () => bytes.slice(a, b).buffer }; } };
    await A.$("fileMsg").dispatch("change", { target: { files: [file] } });
    const r = await talk(A, B, 1.2);
    await until(() => B.log().some((l) => /已接收并解密文件：c\.bin/.test(l)), "文件送达");
    assert.ok(B.$("transcript").children.some((c) => c._text === "call-text"));
    assert.ok(near(r.b.freq, 440, 15) && r.b.rms > 0.2, "文件传输期间语音仍正常");
  });
  await test("挂断：双方状态清空、AudioContext 关闭、麦克风音轨停止；对方收到「已挂断」；之后文字仍互通", async () => {
    await A.$("callEnd").dispatch("click");
    await until(() => !A.api.getCall() && !B.api.getCall(), "双方结束");
    await sleep(30);
    assert.ok(noRunning(A) && noRunning(B), "资源应全部释放");
    assert.match(B.last(), /对方已挂断/);
    B.$("msgIn").value = "after"; await B.$("sendBtn").dispatch("click");
    await until(() => A.$("transcript").children.some((c) => c._text === "after"), "挂断后文字");
    assert.ok(!A.log().some((l) => /认证失败|计数器倒退|跳跃过大/.test(l)) && !B.log().some((l) => /认证失败|计数器倒退|跳跃过大/.test(l)), "全程无棘轮/信封错误");
  });
  await test("拒接：呼叫方收到「对方拒接」", async () => {
    await B.$("callBtn").dispatch("click");
    await until(() => A.api.getCall()?.state === "ring-in", "A 响铃");
    await A.$("callDecline").dispatch("click");
    await until(() => !A.api.getCall() && !B.api.getCall(), "结束");
    assert.match(B.last(), /对方拒接/);
  });
  await test("再次通话（第二通，B 呼 A）仍正常；呼叫方在开麦阶段取消 → 无未处理拒绝、资源释放", async () => {
    await B.$("callBtn").dispatch("click");
    await until(() => A.api.getCall()?.state === "ring-in", "A 响铃");
    await A.$("callAccept").dispatch("click");
    await until(() => A.api.getCall()?.state === "active" && B.api.getCall()?.state === "active", "active");
    const r = await talk(A, B, 0.8); assert.ok(near(r.a.freq, 880, 15) && near(r.b.freq, 440, 15));
    await B.$("callEnd").dispatch("click"); await until(() => !A.api.getCall() && !B.api.getCall(), "结束");
    // 取消竞争：A 发起呼叫，麦克风授权尚未返回时点「取消」
    let release; const gum = A.navigator.mediaDevices.getUserMedia;
    A.navigator.mediaDevices.getUserMedia = () => new Promise((res) => { release = () => res(gum()); });
    A.$("callBtn").dispatch("click"); await sleep(20);
    assert.equal(A.api.getCall()?.state, "prep");
    await A.$("callEnd").dispatch("click"); assert.equal(A.api.getCall(), null);
    release(); await sleep(60);
    A.navigator.mediaDevices.getUserMedia = gum;
    assert.ok(noRunning(A), "取消后 AudioContext 与麦克风都应释放（含授权返回后才拿到的那条音轨）");
    assert.ok(!B.api.getCall(), "对方不应出现来电");
  });
  await test("麦克风中途断开（设备拔出/权限撤销）：本端结束并提示，对方收到「对方出错」", async () => {
    await callAB(A, B); await talk(A, B, 0.4);
    const t = A.tracks[A.tracks.length - 1]; t.readyState = "ended"; t.onended && t.onended();
    await until(() => !A.api.getCall() && !B.api.getCall(), "双方结束");
    assert.match(A.log().slice(-2).join(" "), /麦克风已断开/); assert.match(B.last(), /对方出错/);
  });
  await test("音频上下文被系统挂起时自动 resume", async () => {
    await callAB(A, B);
    const ctx = A.contexts.filter((c) => c.state === "running")[0];
    ctx.state = "suspended"; await sleep(10);
    assert.equal(ctx.state, "running", "onstatechange 应把上下文恢复为 running");
    await A.$("callEnd").dispatch("click"); await until(() => !A.api.getCall() && !B.api.getCall(), "结束");
  });
  await test("对方断线：通话随会话重置而结束，资源释放", async () => {
    await callAB(A, B); await talk(A, B, 0.3);
    A.api.getWs().close();
    await until(() => !B.api.getCall(), "B 结束"); await sleep(30);
    assert.match(B.log().slice(-2).join(" "), /通话已随会话结束/); assert.ok(noRunning(B));
  });
}

console.log("兼容与错误路径");
{
  FLAGS.noWorklet = true;
  const [A, B] = await pair("ROOM-SCRIPT-02");
  await test("浏览器没有 AudioWorklet：自动退回 ScriptProcessor 兼容模式，双向音频仍正确", async () => {
    await callAB(A, B);
    const r = await talk(A, B, 2);
    assert.equal(r.modeA, "script"); assert.equal(r.modeB, "script");
    assert.ok(near(r.a.freq, 880, 15) && r.a.rms > 0.2, `A 听到 ${r.a.freq.toFixed(0)}Hz`);
    assert.ok(near(r.b.freq, 440, 15) && r.b.rms > 0.2, `B 听到 ${r.b.freq.toFixed(0)}Hz`);
    assert.ok(A.log().some((l) => /兼容模式/.test(l)), "应提示已改用兼容模式");
    await A.$("callEnd").dispatch("click"); await until(() => !A.api.getCall() && !B.api.getCall(), "结束");
  });
  FLAGS.noWorklet = false; FLAGS.failAddModule = true;
  await test("AudioWorklet 模块加载被拦（Chrome 抛 AbortError）：不再误报为麦克风被占用，而是退回兼容模式", async () => {
    await callAB(A, B);
    const r = await talk(A, B, 1);
    assert.equal(r.modeA, "script"); assert.ok(near(r.b.freq, 440, 15));
    assert.ok(!A.log().some((l) => /麦克风正被其他应用占用/.test(l)), "不应出现误导性的麦克风占用提示");
    assert.ok(A.log().some((l) => /AbortError/.test(l)), "应写明真实原因");
    await B.$("callEnd").dispatch("click"); await until(() => !A.api.getCall() && !B.api.getCall(), "结束");
  });
  FLAGS.failAddModule = false;
  FLAGS.micRate = 44100; FLAGS.ctxRate = 48000;
  await test("麦克风采样率与上下文不一致（iOS 打开麦克风后切换音频会话）：上下文重建，音频仍正确", async () => {
    await callAB(A, B);
    assert.ok(A.log().some((l) => /音频上下文已按麦克风采样率重建/.test(l)) || A.contexts.filter((c) => c.state === "closed").length >= 1, "应重建上下文");
    assert.equal(A.contexts.filter((c) => c.state === "running").length, 1, "重建后只剩一个运行中的上下文");
    const r = await talk(A, B, 1); assert.ok(near(r.a.freq, 880, 15) && near(r.b.freq, 440, 15));
    await A.$("callEnd").dispatch("click"); await until(() => !A.api.getCall() && !B.api.getCall(), "结束");
    assert.ok(noRunning(A) && noRunning(B));
  });
  FLAGS.micRate = 0;
  await test("呼叫方麦克风被拒：给出权限修复指引，不发出呼叫，资源释放", async () => {
    const gum = A.navigator.mediaDevices.getUserMedia;
    A.navigator.mediaDevices.getUserMedia = async () => { const e = new Error("Permission denied"); e.name = "NotAllowedError"; throw e; };
    await A.$("callBtn").dispatch("click"); await sleep(40);
    assert.equal(A.api.getCall(), null); assert.match(A.last(), /麦克风权限被拒绝/); assert.ok(noRunning(A));
    assert.ok(!B.api.getCall());
    A.navigator.mediaDevices.getUserMedia = gum;
  });
  await test("接听方麦克风不可读（被占用）：接听方提示原因，呼叫方收到「对方出错」", async () => {
    const gum = B.navigator.mediaDevices.getUserMedia;
    B.navigator.mediaDevices.getUserMedia = async () => { const e = new Error("Could not start audio source"); e.name = "NotReadableError"; throw e; };
    await A.$("callBtn").dispatch("click");
    await until(() => B.api.getCall()?.state === "ring-in", "B 响铃");
    await B.$("callAccept").dispatch("click");
    await until(() => !A.api.getCall() && !B.api.getCall(), "结束");
    assert.match(B.log().slice(-2).join(" "), /麦克风正被其他应用占用/); assert.match(A.last(), /对方出错/);
    B.navigator.mediaDevices.getUserMedia = gum;
  });
  await test("双方同时呼叫：各自收到「对方正忙」并退出，之后仍能正常通话", async () => {
    A.$("callBtn").dispatch("click"); B.$("callBtn").dispatch("click");
    await until(() => !A.api.getCall() && !B.api.getCall(), "都退出", 6000);
    assert.match(A.log().join("\n"), /对方正忙/); assert.match(B.log().join("\n"), /对方正忙/);
    await callAB(A, B); const r = await talk(A, B, 0.6); assert.ok(near(r.b.freq, 440, 15));
    await A.$("callEnd").dispatch("click"); await until(() => !A.api.getCall() && !B.api.getCall(), "结束");
  });
}

console.log("真实网络条件");
{
  NET.latency = 120; NET.jitter = 80;
  const [A, B] = await pair("ROOM-NET-03");
  await test("120±80ms 延迟抖动 + 对端时钟慢 1.5%：8 秒通话无棘轮/信封错误，音频连续", async () => {
    await callAB(A, B);
    const r = await talk(A, B, 8, { driftB: 66 });
    assert.ok(near(r.a.freq, 880, 15) && r.a.rms > 0.2, `A 听到 ${r.a.freq.toFixed(0)}Hz rms=${r.a.rms.toFixed(3)}`);
    assert.ok(near(r.b.freq, 440, 15) && r.b.rms > 0.2, `B 听到 ${r.b.freq.toFixed(0)}Hz rms=${r.b.rms.toFixed(3)}`);
    for (const p of [A, B]) assert.ok(!p.log().some((l) => /认证失败|计数器倒退|跳跃过大|过旧/.test(l)), p.tag + " 不应出现棘轮/信封错误");
    await A.$("callEnd").dispatch("click"); await until(() => !A.api.getCall() && !B.api.getCall(), "结束");
    await sleep(600);   // 挂断后仍在路上的语音帧不会让任何一方“复活”通话
    assert.ok(!A.api.getCall() && !B.api.getCall());
  });
  NET.latency = 1; NET.jitter = 0;
}

console.log(`\n全部通过：${passed} 项。`);
process.exit(0);
