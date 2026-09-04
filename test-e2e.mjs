// 端到端仿真（Node 内跑，不需要浏览器）：把 pqsession-net.html 的内联模块在两个“假浏览器”里各评估一次，
// 用假 DOM / 假 WebSocket（直连真实的中继 hub 逻辑）/ 假 AudioContext 驱动完整流程：
//   身份 → 连接 → 交换公钥 → 核对指纹 → 握手 → 文字 → 语音通话（呼叫/接听/双向音频/挂断）→ 断线重连（信任列表自动通过）
// 目的：让“只有真浏览器里才会暴露”的接线错误（元素 id、变量作用域、信令顺序、通话状态机）在这里先炸。
// 运行：node test-e2e.mjs
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { EventEmitter } from "node:events";
import { fileURLToPath } from "node:url";
import { makeHub, makeConnectionHandler, readConfig } from "./server.js";

const ROOT = path.dirname(fileURLToPath(import.meta.url));
const html = fs.readFileSync(path.join(ROOT, "pqsession-net.html"), "utf8");
let src = html.match(/<script type="module">([\s\S]*?)<\/script>/)[1];

// 动态 import 改由假实现提供（沙箱无网络；同时模拟 vendor/ 已存在）
const IMPORT_LOCAL = "await import(new URL(localPath, location.href).href)";
const IMPORT_CDN = "await import(cdnUrl)";
assert.equal(src.split(IMPORT_LOCAL).length, 2, "loadLib 本地 import 形状变了");
assert.equal(src.split(IMPORT_CDN).length, 2, "loadLib CDN import 形状变了");
src = src.replace(IMPORT_LOCAL, "await __fakeImport(localPath)").replace(IMPORT_CDN, "await __fakeImport(cdnUrl)");

const EXPOSE = `
return {
  get call(){ return call; }, get session(){ return session; }, get myIdentity(){ return myIdentity; },
  get peerFp(){ return peerFp; }, get fpVerified(){ return fpVerified; }, get role(){ return role; },
  get roomCtx(){ return roomCtx; }, get ws(){ return ws; }, get trust(){ return trust; }, get ctrRecv(){ return ctrRecv; },
  $,
};`;
const GLOBAL_NAMES = ["document", "window", "navigator", "location", "localStorage", "URL", "Blob", "FileReader",
  "AudioContext", "AudioWorkletNode", "WebSocket", "confirm", "prompt", "alert", "__fakeImport"];
const factory = new Function(...GLOBAL_NAMES, `"use strict"; return (async () => {\n${src}\n${EXPOSE}\n})();`);

// ---- 尺寸忠实的假 KEM / 假 Argon2（只验证协议与接线，不是安全实现） ----
const PK = 1568, SK = 3168, CT = 1568;
const sha = (...bs) => new Uint8Array(crypto.createHash("sha256").update(Buffer.concat(bs.map((b) => Buffer.from(b)))).digest());
const fakeKem = {
  keygen() { const seed = crypto.randomBytes(32); const pk = new Uint8Array(PK); pk.set(sha(seed), 0); const sk = new Uint8Array(SK); sk.set(seed, 0); return { publicKey: pk, secretKey: sk }; },
  encapsulate(pk) { const r = crypto.randomBytes(32); const ct = new Uint8Array(CT); ct.set(r, 0); return { cipherText: ct, sharedSecret: sha(pk.subarray(0, 32), r) }; },
  decapsulate(ct, sk) { return sha(sha(sk.subarray(0, 32)), ct.subarray(0, 32)); },
};
async function fakeArgon2id({ password, salt, hashLength }) {
  const k = await globalThis.crypto.subtle.importKey("raw", password, "PBKDF2", false, ["deriveBits"]);
  return new Uint8Array(await globalThis.crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt, iterations: 500 }, k, hashLength * 8));
}
async function __fakeImport(spec) {
  if (/ml-kem/.test(spec)) return { ml_kem1024: fakeKem };
  if (/hash-wasm/.test(spec)) return { argon2id: fakeArgon2id };
  throw new Error("unknown import " + spec);
}

// ---- 假中继：真实 hub + 真实连接处理器，套在假 WebSocket 上 ----
const hub = makeHub();
const onConn = makeConnectionHandler({ hub, cfg: readConfig({}) });
class FakeWebSocket {
  constructor(url) {
    this.url = url; this.readyState = 0; this.bufferedAmount = 0;
    this.onopen = this.onmessage = this.onclose = this.onerror = null;
    const srv = new EventEmitter();
    srv.send = (s) => setImmediate(() => { if (this.readyState === 1 && this.onmessage) this.onmessage({ data: String(s) }); });
    srv.close = () => setImmediate(() => { srv.emit("close"); this._closed(); });
    srv.terminate = () => { srv.emit("close"); this._closed(); };
    srv.ping = () => {}; srv.pause = () => {}; srv.resume = () => {};
    this._srv = srv;
    onConn(srv);
    setImmediate(() => { this.readyState = 1; this.onopen && this.onopen({}); });
  }
  send(s) { if (this.readyState !== 1) throw new Error("socket not open"); setImmediate(() => this._srv.emit("message", Buffer.from(String(s)), false)); }
  close() { if (this.readyState >= 2) return; this.readyState = 2; setImmediate(() => { this._srv.emit("close"); this._closed(); }); }
  _closed() { if (this.readyState === 3) return; this.readyState = 3; this.onclose && this.onclose({}); }
}

// ---- 假音频 ----
class FakeAudioContext {
  constructor() { this.sampleRate = 48000; this.destination = {}; this.state = "running"; this.audioWorklet = { addModule: async () => {} }; }
  async resume() {} async close() { this.state = "closed"; }
  createMediaStreamSource() { return { connect() {}, disconnect() {} }; }
  createGain() { return { gain: { value: 1 }, connect() {}, disconnect() {} }; }
}
class FakeWorkletNode {
  constructor(ctx, name) { this.name = name; this.port = { onmessage: null, posted: [], postMessage(a) { this.posted.push(a); } }; }
  connect() {} disconnect() {}
}

// ---- 假 DOM ----
function makeEl(id, tag) {
  const el = {
    id, tagName: tag, textContent: "", value: "", disabled: false, checked: false, files: null,
    style: {}, dataset: {}, children: [], _l: {}, scrollTop: 0, scrollHeight: 0,
    classList: {
      _s: new Set(),
      add(...c) { c.forEach((x) => this._s.add(x)); }, remove(...c) { c.forEach((x) => this._s.delete(x)); },
      toggle(c, f) { if (f === undefined) f = !this._s.has(c); f ? this._s.add(c) : this._s.delete(c); return f; },
      contains(c) { return this._s.has(c); },
    },
    addEventListener(t, fn) { (el._l[t] ||= []).push(fn); },
    dispatch(t, ev = {}) { ev.target ||= el; ev.preventDefault ||= () => {}; for (const fn of (el._l[t] || [])) fn(ev); },
    click() { el.dispatch("click"); },
    appendChild(c) { el.children.push(c); c.parentNode = el; if (el._onAppend) el._onAppend(c); return c; },
    append(...cs) { cs.forEach((c) => el.appendChild(c)); }, prepend(c) { el.children.unshift(c); },
    removeChild(c) { el.children = el.children.filter((x) => x !== c); },
    querySelector(sel) { const cls = sel.replace(/^\./, ""); const find = (n) => { for (const c of n.children) { if (c.classList.contains(cls)) return c; const r = find(c); if (r) return r; } return null; }; return find(el); },
    querySelectorAll() { return []; }, focus() {},
    get className() { return [...el.classList._s].join(" "); }, set className(v) { el.classList._s = new Set(String(v).split(/\s+/).filter(Boolean)); },
    get innerHTML() { return ""; }, set innerHTML(v) { if (v === "") el.children = []; },
  };
  return el;
}

async function makeClient(name) {
  const els = new Map();
  const logs = [];
  const document = {
    getElementById(id) { if (!els.has(id)) els.set(id, makeEl(id, "div")); return els.get(id); },
    createElement(tag) { return makeEl(null, tag); },
    querySelectorAll() { return []; },
  };
  document.getElementById("log")._onAppend = (c) => logs.push({ text: c.textContent, color: c.style.color });
  const storage = new Map();
  const localStorage = { getItem: (k) => (storage.has(k) ? storage.get(k) : null), setItem: (k, v) => storage.set(k, String(v)), removeItem: (k) => storage.delete(k) };
  const location = { protocol: "https:", host: "relay.test", href: "https://relay.test/" };
  const window = { crypto: globalThis.crypto, isSecureContext: true, localStorage, AudioContext: FakeAudioContext, prompt: () => null };
  const navigator = { mediaDevices: { getUserMedia: async () => ({ getTracks: () => [{ stop() {} }] }) }, clipboard: { writeText: async () => {} } };
  const api = await factory(document, window, navigator, location, localStorage, URL, Blob, class {}, FakeAudioContext, FakeWorkletNode, FakeWebSocket, () => true, () => null, () => {}, __fakeImport);
  await new Promise((r) => setTimeout(r, 20));      // 等 boot() 里的 ensureNoble()
  const errors = () => logs.filter((l) => l.color === "#ff7a8a").map((l) => l.text);
  return { name, api, $: api.$, logs, errors, storage };
}

async function until(fn, what, ms = 8000) {
  const t0 = Date.now();
  while (Date.now() - t0 < ms) { if (fn()) return; await new Promise((r) => setTimeout(r, 5)); }
  throw new Error("等待超时：" + what);
}
let passed = 0;
async function step(name, fn) { await fn(); passed++; console.log("  ✓ " + name); }
function frame(seed) { const f = new Float32Array(2048); for (let i = 0; i < f.length; i++) f[i] = Math.sin((seed * 2048 + i) / 20) * 0.3; return f; }

const A = await makeClient("A"), B = await makeClient("B");

await step("启动：算法库（假）加载成功，无错误日志", async () => {
  for (const c of [A, B]) { assert.ok(c.$("ch-kem").classList.contains("on"), c.name + " ML-KEM chip"); assert.deepEqual(c.errors(), []); }
});
await step("生成身份：v2 指纹格式；信任列表按身份初始化为空", async () => {
  for (const c of [A, B]) {
    c.$("genBtn").click();
    await until(() => c.api.myIdentity, c.name + " 身份");
    assert.match(c.api.myIdentity.fingerprint, /^([0-9a-f]{4} ){15}[0-9a-f]{4}$/);
    await until(() => c.api.trust && c.api.trust.persistent, c.name + " 信任列表初始化");
    assert.equal(c.api.trust.size, 0);
  }
});
async function connect(c, code = "TESTROOM12") {
  c.$("srvUrl").value = "wss://relay.test"; c.$("roomCode").value = code;
  c.$("connectBtn").click();
}
await step("连接同一房间口令：中继只看到哈希；双方交换加密的公钥，指纹互相对上", async () => {
  await connect(A); await connect(B);
  await until(() => A.api.peerFp && B.api.peerFp, "hello 交换");
  assert.equal(A.api.peerFp, B.api.myIdentity.fingerprint);
  assert.equal(B.api.peerFp, A.api.myIdentity.fingerprint);
  assert.equal(A.api.roomCtx.id, B.api.roomCtx.id);
  assert.match(A.api.roomCtx.id, /^[0-9a-f]{32}$/);
  assert.ok(![...hub.rooms.keys()].some((r) => /TESTROOM12/.test(r)), "中继上的房间名不是口令明文");
  assert.ok(A.$("verifyBtn").disabled && B.$("verifyBtn").disabled, "未勾选时按钮禁用");
  assert.deepEqual(A.errors(), []); assert.deepEqual(B.errors(), []);
});
await step("首次核对：勾选 + 点击 → 握手完成，会话建立；两端信任列表各新增一条", async () => {
  for (const c of [A, B]) { c.$("fpCheck").checked = true; c.$("fpCheck").dispatch("change"); c.$("peerNameIn").value = c.name === "A" ? "小李" : "小王"; assert.equal(c.$("verifyBtn").disabled, false); c.$("verifyBtn").click(); }
  await until(() => A.api.session && B.api.session, "会话建立");
  assert.equal(A.api.trust.size, 1); assert.equal(B.api.trust.size, 1);
  assert.equal(A.api.trust.find(B.api.myIdentity.fingerprint).name, "小李");
  assert.ok([...A.storage.keys()].some((k) => k.startsWith("pqsession.trust.v1.")), "已加密落盘");
  assert.ok(![...A.storage.values()].some((v) => v.includes("小李")), "落盘内容里没有明文名字");
  assert.deepEqual(A.errors(), []); assert.deepEqual(B.errors(), []);
});
await step("文字消息双向送达", async () => {
  A.$("msgIn").value = "你好，B"; A.$("sendBtn").click();
  await until(() => B.$("transcript").children.some((b) => b.textContent === "你好，B"), "B 收到文字");
  B.$("msgIn").value = "你好，A"; B.$("sendBtn").click();
  await until(() => A.$("transcript").children.some((b) => b.textContent === "你好，A"), "A 收到文字");
});
await step("语音通话：A 呼叫 → B 来电 → 接听 → 双方 active", async () => {
  assert.equal(A.$("callBtn").disabled, false);
  A.$("callBtn").click();
  await until(() => B.api.call && B.api.call.state === "ring-in", "B 来电");
  assert.equal(A.api.call.state, "ring");
  B.$("callAccept").click();
  await until(() => A.api.call && A.api.call.state === "active" && B.api.call && B.api.call.state === "active", "双方通话中");
  assert.deepEqual(A.errors(), []); assert.deepEqual(B.errors(), []);
});
await step("语音帧：A→B、B→A 各送 40 块采集数据，对端播放节点收到解码后的音频帧，无错误", async () => {
  for (let i = 0; i < 40; i++) A.api.call.cap.port.onmessage({ data: frame(i) });
  await until(() => B.api.call && B.api.call.play.port.posted.length >= 20, "B 收到语音");
  for (let i = 0; i < 40; i++) B.api.call.cap.port.onmessage({ data: frame(100 + i) });
  await until(() => A.api.call && A.api.call.play.port.posted.length >= 20, "A 收到语音");
  const f = B.api.call.play.port.posted[5];
  assert.ok(f instanceof Float32Array && f.length === 2880, "16k→48k 重采样后每包 2880 样本");
  assert.ok(f.some((v) => Math.abs(v) > 0.01), "解码出的不是静音");
  assert.deepEqual(A.errors(), []); assert.deepEqual(B.errors(), []);
});
await step("通话中发文字不互踩棘轮", async () => {
  A.$("msgIn").value = "通话中的文字"; A.$("sendBtn").click();
  for (let i = 0; i < 10; i++) A.api.call.cap.port.onmessage({ data: frame(500 + i) });
  await until(() => B.$("transcript").children.some((b) => b.textContent === "通话中的文字"), "B 收到通话中的文字");
  assert.deepEqual(B.errors(), []);
});
await step("挂断：A 点挂断 → 双方通话结束，B 日志显示对方已挂断", async () => {
  A.$("callEnd").click();
  await until(() => !A.api.call && !B.api.call, "双方挂断");
  assert.ok(B.logs.some((l) => /对方已挂断/.test(l.text)), "B 收到挂断原因");
  assert.deepEqual(A.errors(), []); assert.deepEqual(B.errors(), []);
});
await step("第二次通话（重新开麦、重新装载 worklet）同样正常", async () => {
  B.$("callBtn").click();
  await until(() => A.api.call && A.api.call.state === "ring-in", "A 来电");
  A.$("callAccept").click();
  await until(() => A.api.call && A.api.call.state === "active" && B.api.call && B.api.call.state === "active", "第二次通话中");
  for (let i = 0; i < 20; i++) B.api.call.cap.port.onmessage({ data: frame(900 + i) });
  await until(() => A.api.call && A.api.call.play.port.posted.length >= 5, "A 收到第二次通话语音");
  B.$("callEnd").click();
  await until(() => !A.api.call && !B.api.call, "第二次挂断");
  assert.deepEqual(A.errors(), []); assert.deepEqual(B.errors(), []);
});
await step("B 断线重连：A 收到离开并重置；重连后两端按信任列表自动通过核对，无需点击即握手成功", async () => {
  B.$("disconnectBtn").click();
  await until(() => !A.api.session && !B.api.session, "会话重置");
  await new Promise((r) => setTimeout(r, 30));
  await connect(B);
  await until(() => A.api.session && B.api.session, "自动重建会话", 10000);
  assert.match(A.$("verifyState").textContent, /自动/);
  assert.match(B.$("verifyState").textContent, /自动/);
  assert.equal(A.api.trust.find(B.api.myIdentity.fingerprint).count, 2);
  assert.deepEqual(A.errors(), []); assert.deepEqual(B.errors(), []);
});
await step("重连后的会话里语音仍可用", async () => {
  A.$("callBtn").click();
  await until(() => B.api.call && B.api.call.state === "ring-in", "来电");
  B.$("callAccept").click();
  await until(() => A.api.call && A.api.call.state === "active" && B.api.call && B.api.call.state === "active", "通话中");
  for (let i = 0; i < 20; i++) A.api.call.cap.port.onmessage({ data: frame(2000 + i) });
  await until(() => B.api.call && B.api.call.play.port.posted.length >= 5, "B 收到语音");
  B.$("callEnd").click();
  await until(() => !A.api.call && !B.api.call, "挂断");
  assert.deepEqual(A.errors(), []); assert.deepEqual(B.errors(), []);
});

console.log(`\n端到端仿真全部通过：${passed} 步。`);
process.exit(0);
