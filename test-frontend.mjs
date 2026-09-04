// 前端密码学层测试（Node 内跑，不需要浏览器）：从 pqsession-net.html 提取第 1、2 段（内核 + 会话层）
// 与第 3 段中的房间信封函数，注入“尺寸忠实”的假 KEM（ML-KEM-1024 的 pk/sk/ct/ss 长度）来验证
// 握手、棘轮、v2 的“先验证后提交”、长度校验、指纹格式与房间信封。运行：node test-frontend.mjs
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath, pathToFileURL } from "node:url";

const ROOT = path.dirname(fileURLToPath(import.meta.url));
const html = fs.readFileSync(path.join(ROOT, "pqsession-net.html"), "utf8");
const src = html.match(/<script type="module">([\s\S]*?)<\/script>/)[1];
const marker = src.indexOf("* 第 3 段 / 3");
assert.ok(marker > 0, "找不到第 3 段标记");
const core = src.slice(0, src.lastIndexOf("/* ====", marker));

function grab(name) {
  const re = new RegExp(`\\n(async function ${name}\\([^)]*\\)\\{[\\s\\S]*?\\n\\})\\n`);
  const m = src.match(re); assert.ok(m, "提取失败 " + name); return m[1];
}
function grabFn(name) {
  const re = new RegExp(`\\n(function ${name}\\([^)]*\\)\\{[\\s\\S]*?\\n\\})\\n`);
  const m = src.match(re); assert.ok(m, "提取失败 " + name); return m[1];
}
function grabLine(name) {   // 单行函数
  const re = new RegExp(`\\n(function ${name}\\([^)]*\\)\\{.*\\})\\n`);
  const m = src.match(re); assert.ok(m, "提取失败 " + name); return m[1];
}
const glue = `
const subtle = globalThis.crypto.subtle;
function randomBytes(n){ const o=new Uint8Array(n); globalThis.crypto.getRandomValues(o); return o; }
const dec = new TextDecoder();
const hexId = (b)=>Array.from(b).map(x=>x.toString(16).padStart(2,"0")).join("");
${src.match(/const ROOM_AAD = L\("PQSESS-room-v2"\);\nconst KIND_HELLO=1[^\n]*\nconst ROOM_MAX_ENV[^\n]*\n/)[0]}
let roomCtx = null;
${grabFn("normalizeRoomCode")}
${grab("sealKind")}
${grab("unsealKind")}
${src.match(/const REPLAY_WIN = [^\n]*\n/)[0]}
${grabFn("replayWindowAccept")}
${grabFn("randomRoom")}
${src.match(/const TRUST_KEY = [^\n]*\nconst TRUST_MAX = [^\n]*\nconst FP_RE = [^\n]*\nconst TRUST_AAD = [^\n]*\n/)[0]}
${grabFn("makeTrustStore")}
${grab("trustSealText")}
${grab("trustOpenText")}
${grabFn("makeEncryptedBackend")}
let call = null;
${grabLine("vcSleep")}
${grabFn("vcResume")}
${grabFn("vcOpenMic")}
function setCall(c){ call = c; }
export { createPQCrypto, createPQSession, normalizeRoomCode, sealKind, unsealKind, randomRoom, setRoom, getRoom, makeTrustStore, trustSealText, trustOpenText, makeEncryptedBackend, vcResume, vcOpenMic, setCall };
function setRoom(r){ roomCtx = r; } function getRoom(){ return roomCtx; }
`;
// glue 依赖 pq / toB64 / fromB64 / enc / L：这些在测试里注入
const modText = core + "\n" + glue.replace("export {", "let pq, toB64, fromB64; export function bindPq(p){ pq=p; toB64=(b)=>p.b64encode(b); fromB64=(s)=>p.b64decode(s); }\nexport {");
const tmp = path.join(ROOT, ".test-crypto-extract.mjs");
fs.writeFileSync(tmp, modText);
const mod = await import(pathToFileURL(tmp).href + "?t=" + Date.now());
fs.unlinkSync(tmp);

// ---- 尺寸忠实的假 KEM（仅用于测试协议逻辑；不是密码学安全的 KEM） ----
const PK = 1568, SK = 3168, CT = 1568;
const sha = (...bs) => new Uint8Array(crypto.createHash("sha256").update(Buffer.concat(bs.map((b) => Buffer.from(b)))).digest());
const fakeKem = {
  keygen() { const seed = crypto.randomBytes(32); const pk = new Uint8Array(PK); pk.set(sha(seed), 0); const sk = new Uint8Array(SK); sk.set(seed, 0); return { publicKey: pk, secretKey: sk }; },
  encapsulate(pk) { assert.equal(pk.length, PK); const r = crypto.randomBytes(32); const ct = new Uint8Array(CT); ct.set(r, 0); return { cipherText: ct, sharedSecret: sha(pk.subarray(0, 32), r) }; },
  decapsulate(ct, sk) { assert.equal(ct.length, CT); assert.equal(sk.length, SK); return sha(sha(sk.subarray(0, 32)), ct.subarray(0, 32)); },
};
async function fakeArgon({ password, salt, hashLen }) {   // 测试用：PBKDF2 代替 Argon2id（只验证信封逻辑）
  const k = await globalThis.crypto.subtle.importKey("raw", password, "PBKDF2", false, ["deriveBits"]);
  return new Uint8Array(await globalThis.crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt, iterations: 1000 }, k, hashLen * 8));
}
const pq = mod.createPQSession({ subtle: globalThis.crypto.subtle, randomBytes: (n) => new Uint8Array(crypto.randomBytes(n)), mlkem: fakeKem, argon2id: fakeArgon });
mod.bindPq(pq);
const enc = new TextEncoder(), dec = new TextDecoder();
let passed = 0;
async function test(name, fn) { await fn(); passed++; console.log("  ✓ " + name); }

console.log("指纹 / 公钥校验");
await test("v2 指纹：256 位、16 组 4 位十六进制；不同于旧版 8 字节格式", async () => {
  const a = await pq.generateKeypair();
  assert.match(a.fingerprint, /^([0-9a-f]{4} ){15}[0-9a-f]{4}$/);
  const again = await pq.fingerprint(pq.b64decode(a.pub.x25519_pub), pq.b64decode(a.pub.mlkem_pub));
  assert.equal(again, a.fingerprint);
});
await test("validatePub：算法名 / 长度 / 类型不符一律拒绝", async () => {
  const a = await pq.generateKeypair();
  assert.deepEqual(Object.keys(pq.validatePub(a.pub)), ["x", "m"]);
  assert.throws(() => pq.validatePub({ ...a.pub, alg: "X25519" }), /算法/);
  assert.throws(() => pq.validatePub({ ...a.pub, x25519_pub: a.pub.x25519_pub.slice(4) }), /长度/);
  assert.throws(() => pq.validatePub({ ...a.pub, mlkem_pub: 12 }), /缺失/);
  assert.throws(() => pq.validatePub(null), /无效/);
});

console.log("握手 / 棘轮");
async function handshake() {
  const A = await pq.generateKeypair(), B = await pq.generateKeypair();
  const { invite, pending } = await pq.sessionInvite(A.key, B.pub);
  assert.equal(invite.length, 3181);
  const { accept, session: sb } = await pq.sessionAccept(B.key, A.pub, invite);
  assert.equal(accept.length, 3213);
  const { session: sa } = await pq.sessionComplete(pending, accept);
  assert.equal(pending.eaPriv, null, "握手完成后一次性私钥已清零/释放");
  assert.equal(pending.k1, null);
  return { A, B, sa, sb };
}
await test("完整握手 + 双向消息 + 会话 ID 一致", async () => {
  const { sa, sb } = await handshake();
  assert.equal(pq.hex(sa.sid), pq.hex(sb.sid));
  const c1 = await pq.ratchetEncrypt(sa, enc.encode("hi B"));
  assert.equal(dec.decode(await pq.ratchetDecrypt(sb, c1)), "hi B");
  const c2 = await pq.ratchetEncrypt(sb, enc.encode("hi A"));
  assert.equal(dec.decode(await pq.ratchetDecrypt(sa, c2)), "hi A");
  await assert.rejects(pq.ratchetDecrypt(sb, c1), /重放/);
  await assert.rejects(pq.ratchetDecrypt(sa, c1), /方向/);
});
await test("握手数据长度不符 / 确认值被篡改 → 拒绝", async () => {
  const A = await pq.generateKeypair(), B = await pq.generateKeypair();
  const { invite, pending } = await pq.sessionInvite(A.key, B.pub);
  await assert.rejects(pq.sessionAccept(B.key, A.pub, invite.subarray(0, invite.length - 1)), /长度或魔数/);
  await assert.rejects(pq.sessionAccept(B.key, A.pub, pq.concatBytes(invite, new Uint8Array(1))), /长度或魔数/);
  const { accept } = await pq.sessionAccept(B.key, A.pub, invite);
  const bad = accept.slice(); bad[bad.length - 1] ^= 1;
  await assert.rejects(pq.sessionComplete({ ...pending }, bad), /密钥确认失败/);
});
await test("中间人换掉 B 的身份：A 的密钥确认失败", async () => {
  const A = await pq.generateKeypair(), B = await pq.generateKeypair(), M = await pq.generateKeypair();
  const { invite, pending } = await pq.sessionInvite(A.key, B.pub);       // A 相信自己在和 B 谈
  const { accept } = await pq.sessionAccept(M.key, A.pub, invite);        // 但应答的是 M
  await assert.rejects(pq.sessionComplete(pending, accept), /密钥确认失败/);
});
await test("乱序：跳号消息被缓存，迟到消息仍可解；解密成功后缓存项删除", async () => {
  const { sa, sb } = await handshake();
  const cs = []; for (let i = 0; i < 5; i++) cs.push(await pq.ratchetEncrypt(sa, enc.encode("m" + i)));
  assert.equal(dec.decode(await pq.ratchetDecrypt(sb, cs[4])), "m4");
  assert.equal(sb.skipped.size, 4);
  assert.equal(dec.decode(await pq.ratchetDecrypt(sb, cs[1])), "m1");
  assert.equal(sb.skipped.size, 3);
  await assert.rejects(pq.ratchetDecrypt(sb, cs[1]), /重放/);
});
await test("先验证后提交：伪造的高序号帧认证失败时，链状态与缓存完全不变；真消息随后照常解密", async () => {
  const { sa, sb } = await handshake();
  const real = await pq.ratchetEncrypt(sa, enc.encode("real"));
  const forged = real.slice(); forged[20] = 0xff; forged[21] = 0xf0;      // 序号改成很大但 ≤ MAX_SKIP？先改成 +200
  const hdrN = 8 + 1 + 8 + 1;                                           // n 的偏移
  forged.set([0, 0, 0, 200], hdrN);
  const before = { n: sb.nRecv, ck: Buffer.from(sb.ckRecv).toString("hex"), size: sb.skipped.size };
  await assert.rejects(pq.ratchetDecrypt(sb, forged), /认证失败/);
  assert.equal(sb.nRecv, before.n, "接收计数器未被推进");
  assert.equal(Buffer.from(sb.ckRecv).toString("hex"), before.ck, "接收链密钥未被推进");
  assert.equal(sb.skipped.size, before.size, "缓存未增长");
  assert.equal(dec.decode(await pq.ratchetDecrypt(sb, real)), "real");
});
await test("跳跃超过 MAX_SKIP 直接拒绝（零计算成本），状态不变", async () => {
  const { sa, sb } = await handshake();
  const c = await pq.ratchetEncrypt(sa, enc.encode("x"));
  const far = c.slice(); far.set([0, 0, 0x10, 0], 18);                    // n = 4096
  await assert.rejects(pq.ratchetDecrypt(sb, far), /跳跃过大/);
  assert.equal(sb.nRecv, 0);
  assert.equal(dec.decode(await pq.ratchetDecrypt(sb, c)), "x");
});
await test("缓存项对应的真消息认证失败时，密钥不会被误删（旧版会删）", async () => {
  const { sa, sb } = await handshake();
  const c0 = await pq.ratchetEncrypt(sa, enc.encode("m0"));
  const c1 = await pq.ratchetEncrypt(sa, enc.encode("m1"));
  await pq.ratchetDecrypt(sb, c1);
  const tampered = c0.slice(); tampered[tampered.length - 1] ^= 1;
  await assert.rejects(pq.ratchetDecrypt(sb, tampered), /认证失败/);
  assert.equal(sb.skipped.size, 1);
  assert.equal(dec.decode(await pq.ratchetDecrypt(sb, c0)), "m0");
});
await test("缓存总量受 MAX_SKIP_TOTAL 约束（淘汰最旧）", async () => {
  const { sa, sb } = await handshake();
  const cs = []; for (let i = 0; i < 1300; i++) cs.push(await pq.ratchetEncrypt(sa, enc.encode("m" + i)));
  await pq.ratchetDecrypt(sb, cs[500]);      // 缓存 0..499
  await pq.ratchetDecrypt(sb, cs[1000]);     // 缓存 501..999 → 总量 999
  await pq.ratchetDecrypt(sb, cs[1299]);     // 缓存 1001..1298 → 总量 1297 → 淘汰到 1024
  assert.equal(sb.skipped.size, pq.MAX_SKIP_TOTAL);
  await assert.rejects(pq.ratchetDecrypt(sb, cs[0]), /重放/, "最旧的已被淘汰");
  assert.equal(dec.decode(await pq.ratchetDecrypt(sb, cs[1298])), "m1298");
});
await test("sessionWipe 清零链密钥与缓存", async () => {
  const { sa } = await handshake();
  const ck = sa.ckSend;
  pq.sessionWipe(sa);
  assert.ok(ck.every((b) => b === 0)); assert.equal(sa.skipped.size, 0);
});

console.log("房间信封（v2）");
await test("口令规范化：大小写 / 空格 / 连字符 / NFKC 全角", () => {
  assert.equal(mod.normalizeRoomCode(" k7m2-qprs 4x "), "K7M2QPRS4X");
  assert.equal(mod.normalizeRoomCode("ｋ７ｍ２"), "K7M2");
});
await test("随机口令：长度 10、只含无歧义字符、无取模偏差（统计粗检）", () => {
  const counts = {};
  for (let i = 0; i < 3000; i++) { const r = mod.randomRoom(); assert.match(r, /^[ABCDEFGHJKMNPQRSTUVWXYZ23456789]{10}$/); for (const ch of r) counts[ch] = (counts[ch] || 0) + 1; }
  const vals = Object.values(counts); const mean = 30000 / 31;
  assert.ok(vals.every((v) => Math.abs(v - mean) < mean * 0.25), "分布应大致均匀");
});
async function mkRoom(code) {
  const codeBytes = enc.encode(code);
  const raw = await fakeArgon({ password: codeBytes, salt: new Uint8Array(16), hashLen: 32 });
  const key = await globalThis.crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt", "decrypt"]);
  const tag = new Uint8Array(crypto.randomBytes(8));
  return { id: "x", key, tag, tagHex: Buffer.from(tag).toString("hex"), ctr: 0, seen: new Map() };
}
await test("信封：同口令互通、类型 / 载荷完整；反射自己的帧被忽略；计数器倒退判重放；错口令认证失败", async () => {
  const rA = await mkRoom("SAME"), rB = await mkRoom("SAME"), rX = await mkRoom("OTHER");
  mod.setRoom(rA);
  const e1 = await mod.sealKind(1, enc.encode("{\"hello\":1}"));
  const e2 = await mod.sealKind(4, new Uint8Array([9, 9, 9]));
  assert.deepEqual(Object.keys(e1), ["v", "n", "c"]);
  assert.equal(await mod.unsealKind(e1), null, "自己的帧被反射回来：忽略");
  mod.setRoom(rB);
  const f1 = await mod.unsealKind(e1);
  assert.equal(f1.kind, 1); assert.equal(dec.decode(f1.payload), "{\"hello\":1}");
  const f2 = await mod.unsealKind(e2);
  assert.equal(f2.kind, 4); assert.deepEqual(Array.from(f2.payload), [9, 9, 9]);
  await assert.rejects(mod.unsealKind(e1), /重放/, "重放旧帧");
  // 乱序容忍：窗口内先到的高序号不会让后到的低序号被误杀；但每个序号只接受一次
  mod.setRoom(rA);
  const e3 = await mod.sealKind(4, new Uint8Array([3])), e4 = await mod.sealKind(4, new Uint8Array([4])), e5 = await mod.sealKind(4, new Uint8Array([5]));
  mod.setRoom(rB);
  assert.deepEqual(Array.from((await mod.unsealKind(e5)).payload), [5]);
  assert.deepEqual(Array.from((await mod.unsealKind(e3)).payload), [3], "窗口内乱序到达仍接受");
  assert.deepEqual(Array.from((await mod.unsealKind(e4)).payload), [4]);
  await assert.rejects(mod.unsealKind(e4), /重放/, "同一序号第二次被拒");
  await assert.rejects(mod.unsealKind(e3), /重放/);
  mod.setRoom(rA); rA.ctr = 500; const far = await mod.sealKind(4, new Uint8Array([9])); mod.setRoom(rB);
  await mod.unsealKind(far);
  await assert.rejects(mod.unsealKind(e5), /重放/, "比窗口还旧的帧被拒");
  const tampered = { ...e2, c: e2.c.slice(0, -4) + (e2.c.endsWith("AAAA") ? "BBBB" : "AAAA") };
  await assert.rejects(mod.unsealKind(tampered), /认证失败/);
  await assert.rejects(mod.unsealKind({ v: 1, n: e1.n, c: e1.c }), /格式无效/);
  await assert.rejects(mod.unsealKind({ v: 2, n: e1.n, c: 5 }), /格式无效/);
  mod.setRoom(rX);
  await assert.rejects(mod.unsealKind(e2), /认证失败/, "口令不同");
});

console.log("信任存储（v2.1）");
const fpA = (await pq.generateKeypair()).fingerprint, fpB = (await pq.generateKeypair()).fingerprint, fpC = (await pq.generateKeypair()).fingerprint;
const ROOM1 = "0123456789abcdef0123456789abcdef", ROOM2 = "ffffffffffffffffffffffffffffffff";
// 假后端：模拟 localStorage 之上的（未加密）异步后端；read 可返回 null / 文本 / false（解不开）
function fakeBackend(initial) {
  const st = { text: initial === undefined ? null : initial, writes: 0 };
  return { st, read: async () => st.text, write: async (t) => { st.text = t; st.writes++; }, remove: () => { st.text = null; } };
}
await test("持久化：remember 后新建实例仍能 find；touch 累计次数；名字规范化；房间记录随存", async () => {
  let t = 1000; const be = fakeBackend();
  const a = mod.makeTrustStore(be, () => t);
  assert.equal(await a.load(), "empty"); assert.equal(a.persistent, true); assert.equal(a.size, 0); assert.equal(a.find(fpA), null);
  a.remember(fpA, "  小王 "); t = 2000; a.touch(fpA); a.setRoomPeer(ROOM1, fpA); await a.save();
  const b = mod.makeTrustStore(be, () => t);
  assert.equal(await b.load(), "ok");
  const e = b.find(fpA);
  assert.ok(e); assert.equal(e.name, "小王"); assert.equal(e.count, 2); assert.equal(e.first, 1000); assert.equal(e.last, 2000);
  assert.deepEqual(b.roomPeer(ROOM1), { fp: fpA, at: 2000 }); assert.equal(b.roomPeer(ROOM2), null); assert.equal(b.roomPeer(5), null);
  assert.equal(b.byName("小王").fp, fpA); assert.equal(b.byName("  "), null);
  assert.equal(b.remember("not a fingerprint", "x"), null);
  assert.equal(b.setRoomPeer("not-a-room", fpA), false);
});
await test("状态机：无后端=内存；后端抛异常=denied；解不开(false)/坏 JSON=corrupted 但仍持久", async () => {
  const mem = mod.makeTrustStore(null);
  assert.equal(await mem.load(), "memory"); assert.equal(mem.persistent, false); mem.remember(fpA, "a"); assert.ok(mem.find(fpA));
  const bad = mod.makeTrustStore({ read: async () => { throw new Error("denied"); }, write: async () => { throw new Error("denied"); } });
  assert.equal(await bad.load(), "denied"); assert.equal(bad.persistent, false);
  const unreadable = mod.makeTrustStore({ read: async () => false, write: async () => {} });
  assert.equal(await unreadable.load(), "corrupted"); assert.equal(unreadable.persistent, true); assert.equal(unreadable.size, 0);
  const corrupt = mod.makeTrustStore(fakeBackend("{not json"));
  assert.equal(await corrupt.load(), "corrupted"); assert.equal(corrupt.persistent, true); assert.equal(corrupt.size, 0);
  const wfail = mod.makeTrustStore({ read: async () => null, write: async () => { throw new Error("quota"); } });
  await wfail.load(); wfail.remember(fpA, ""); await wfail.save();
  assert.equal(wfail.persistent, false, "写失败后标记为不持久");
});
await test("sanitize：垃圾条目被丢弃、重复指纹去重、总量封顶；房间记录同样清洗与封顶", async () => {
  const junk = [{ fp: fpA, name: 5, count: "x" }, { fp: "zzz" }, null, 7, { fp: fpA, name: "dup" }, { fp: fpB, name: "b", prev: ["nope", fpC], first: -1 }];
  const rooms = { [ROOM1]: { fp: fpA, at: 9 }, "bad": { fp: fpA }, [ROOM2]: { fp: "zzz" }, "0000000000000000000000000000000a": { fp: fpB, at: "x" } };
  const t = mod.makeTrustStore(fakeBackend(JSON.stringify({ v: 1, entries: junk, rooms })), () => 5);
  assert.equal(await t.load(), "ok");
  assert.equal(t.size, 2);
  assert.deepEqual(t.find(fpA), { fp: fpA, name: "", first: 5, last: 5, count: 1, prev: [] });
  assert.deepEqual(t.find(fpB).prev, [fpC]);
  assert.deepEqual(t.roomPeer(ROOM1), { fp: fpA, at: 9 }); assert.equal(t.roomPeer(ROOM2), null);
  assert.deepEqual(t.roomPeer("0000000000000000000000000000000a"), { fp: fpB, at: 5 });
  const many = []; for (let i = 0; i < 600; i++) { const h = ("0000" + i.toString(16)).slice(-4); many.push({ fp: (h + " ").repeat(15) + h }); }
  const manyRooms = {}; for (let i = 0; i < 600; i++) manyRooms[("0".repeat(32) + i.toString(16)).slice(-32)] = { fp: fpA, at: i + 1 };
  const big = mod.makeTrustStore(fakeBackend(JSON.stringify({ v: 1, entries: many, rooms: manyRooms })));
  await big.load();
  assert.equal(big.size, 500);
  assert.equal(JSON.parse(big.serialize()).rooms && Object.keys(JSON.parse(big.serialize()).rooms).length, 500);
  assert.equal(big.roomPeer(("0".repeat(32) + (0).toString(16)).slice(-32)), null, "最旧的房间记录被淘汰");
});
await test("密钥变更：replaceKey 把旧指纹记入 prev、计数归零、吞并重复条目；remove 连带清房间；clear 删后端", async () => {
  let now = 10; const be = fakeBackend(); const t = mod.makeTrustStore(be, () => now); await t.load();
  t.remember(fpA, "小王"); t.touch(fpA); t.remember(fpB, ""); t.setRoomPeer(ROOM1, fpB);
  now = 20; const e = t.replaceKey("小王", fpB);
  assert.equal(e.fp, fpB); assert.deepEqual(e.prev, [fpA]); assert.equal(e.count, 1); assert.equal(e.first, 20);
  assert.equal(t.size, 1, "原来的 fpB 无名条目被吞并"); assert.equal(t.find(fpA), null);
  assert.equal(t.replaceKey("小王", fpB), e, "同一指纹不重复记录");
  assert.equal(t.replaceKey("不存在", fpC), null);
  assert.equal(t.remove(fpB), true); assert.equal(t.remove(fpB), false); assert.equal(t.size, 0);
  assert.equal(t.roomPeer(ROOM1), null, "删除联系人时清掉指向它的房间记录");
  t.remember(fpC, "c"); await t.save(); assert.ok(be.st.text);
  await t.clear(); assert.equal(t.size, 0); assert.equal(be.st.text, null, "清空后后端里不留密文");
});
await test("导出 / 导入：合并同指纹与房间记录、拒绝非本应用的文件", async () => {
  const a = mod.makeTrustStore(fakeBackend(), () => 1); await a.load();
  a.remember(fpA, "a"); a.remember(fpB, ""); a.setRoomPeer(ROOM1, fpA);
  const text = JSON.stringify(a.exportObj());
  const b = mod.makeTrustStore(fakeBackend(), () => 2); await b.load();
  b.remember(fpB, "b"); b.setRoomPeer(ROOM1, fpB);
  assert.deepEqual(b.importText(text), { added: 1, merged: 1 });
  assert.equal(b.find(fpB).name, "b"); assert.equal(b.find(fpB).count, 2); assert.equal(b.find(fpB).first, 1);
  assert.equal(b.find(fpA).name, "a");
  assert.equal(b.roomPeer(ROOM1).fp, fpB, "本机更新的房间记录不被旧的导入覆盖");
  assert.throws(() => b.importText("{"), /JSON/);
  assert.throws(() => b.importText(JSON.stringify({ app: "other", v: 1, entries: [] })), /不是 pqsession/);
  assert.equal(b.list()[0].last >= b.list()[1].last, true, "按最近时间排序");
});
await test("加密后端：往返一致；换命名空间 / 篡改密文解不开；读到垃圾返回 false；写入后 storage 里只有密文", async () => {
  const raw = crypto.randomBytes(32);
  const key = await globalThis.crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt", "decrypt"]);
  const ns = "0011223344556677889900aabbccddee";
  const blob = await mod.trustSealText(key, ns, "{\"v\":1,\"entries\":[]}");
  assert.equal(await mod.trustOpenText(key, ns, blob), "{\"v\":1,\"entries\":[]}");
  await assert.rejects(mod.trustOpenText(key, "ffffffffffffffffffffffffffffffff", blob));
  const tampered = blob.slice(0, -4) + (blob.endsWith("AAAA") ? "BBBB" : "AAAA");
  await assert.rejects(mod.trustOpenText(key, ns, tampered));
  await assert.rejects(mod.trustOpenText(key, ns, "AAAA"));
  const m = new Map();
  const storage = { getItem: (k) => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, v), removeItem: (k) => m.delete(k) };
  const be = mod.makeEncryptedBackend(ns, key, storage);
  assert.equal(await be.read(), null);
  const t = mod.makeTrustStore(be, () => 7); await t.load();
  t.remember(fpA, "小王"); await t.save();
  const stored = m.get("pqsession.trust.v1." + ns);
  assert.ok(stored && !stored.includes("小王") && !stored.includes(fpA.slice(0, 9)), "存储里没有明文");
  const t2 = mod.makeTrustStore(mod.makeEncryptedBackend(ns, key, storage)); assert.equal(await t2.load(), "ok"); assert.equal(t2.find(fpA).name, "小王");
  m.set("pqsession.trust.v1." + ns, "garbage!!");
  assert.equal(await be.read(), false);
  const t3 = mod.makeTrustStore(be); assert.equal(await t3.load(), "corrupted");
  await t3.clear(); assert.equal(m.has("pqsession.trust.v1." + ns), false);
});

console.log("语音：麦克风权限弹窗（行为 + 静态检查）");
// 浏览器环境替身：AudioContext / getUserMedia 都可控，用来观察调用时机而非真去开麦克风
function stubAudioEnv({ resumeSettles }) {
  const prevWindow = globalThis.window, prevNav = Object.getOwnPropertyDescriptor(globalThis, "navigator");
  const env = { gumCalls: 0, ctxCreated: 0, stopped: 0, resolveGum: null };
  env.stream = { getTracks: () => [{ stop() { env.stopped++; } }] };
  globalThis.window = {
    AudioContext: function () {
      env.ctxCreated++; this.state = "running";
      this.resume = () => (resumeSettles ? Promise.resolve() : new Promise(() => {}));
    },
  };
  Object.defineProperty(globalThis, "navigator", {
    value: { mediaDevices: { getUserMedia: () => { env.gumCalls++; return new Promise((r) => { env.resolveGum = r; }); } } },
    configurable: true, writable: true,
  });
  env.restore = () => {
    globalThis.window = prevWindow;
    if (prevNav) Object.defineProperty(globalThis, "navigator", prevNav); else delete globalThis.navigator;
  };
  return env;
}
// getUserMedia 必须在点击事件的同步块内调用：任何先行的 await 都会结束「瞬时用户激活」，
// Safari/iOS 会不弹窗直接拒绝，Chrome 则可能卡在永不 settle 的 resume() 上。
// 这类问题在 Node 里跑不出来，只能对源码做结构性断言，防止回归。
function bodyOf(name) {
  const i = src.indexOf(`function ${name}(`);
  assert.ok(i >= 0, "找不到函数 " + name);
  const start = src.indexOf("{", i);
  let depth = 0, j = start;
  for (; j < src.length; j++) {
    if (src[j] === "{") depth++;
    else if (src[j] === "}") { depth--; if (depth === 0) break; }
  }
  assert.ok(depth === 0, "括号未配平 " + name);
  return src.slice(start + 1, j);
}
// 注释里出现 await / resume 字样不算实现，剥掉后再判断
const stripComments = (t) => t.replace(/\/\*[\s\S]*?\*\//g, "").replace(/(^|[^:])\/\/[^\n]*/g, "$1");
const codeOf = (name) => stripComments(bodyOf(name));
await test("vcOpenMic 内不含 await，且同时发起 AudioContext 与 getUserMedia", () => {
  const b = codeOf("vcOpenMic");
  assert.ok(/getUserMedia/.test(b), "应发起 getUserMedia");
  assert.ok(/new \(window\.AudioContext/.test(b), "应同步创建 AudioContext");
  assert.ok(!/\bawait\b/.test(b), "vcOpenMic 内不得出现 await：会终止用户激活");
  assert.ok(/c\.dead[\s\S]*stop\(\)/.test(b), "取消后若用户仍点允许，必须停掉轨道");
});
await test("vcStart / vcAccept 在第一个 await 之前调用 vcOpenMic", () => {
  for (const fn of ["vcStart", "vcAccept"]) {
    const b = codeOf(fn);
    const open = b.indexOf("vcOpenMic(");
    const firstAwait = b.search(/\bawait\b/);
    assert.ok(open >= 0, fn + " 必须调用 vcOpenMic");
    assert.ok(firstAwait >= 0, fn + " 应当有 await（等待授权结果）");
    assert.ok(open < firstAwait, fn + " 必须在任何 await 之前开麦，否则不会弹权限窗");
  }
});
await test("resume() 一律配超时；vcAudioUp 等的是 micP 而不是裸 resume", () => {
  assert.ok(/Promise\.race/.test(codeOf("vcResume")), "resume() 可能永不 settle，必须 race 超时");
  const b = codeOf("vcAudioUp");
  assert.ok(/await c\.micP/.test(b), "应等待 vcOpenMic 发起的 micP");
  assert.ok(!/await\s+ctx\.resume\s*\(/.test(b), "不得直接 await ctx.resume()：可能永不返回");
  assert.ok(b.indexOf("await c.micP") < b.indexOf("audioWorklet"), "先拿到麦克风再装载 worklet");
});
await test("行为：getUserMedia 在 vcOpenMic 返回前就已发起（同一同步块 → 才会弹权限窗）", async () => {
  const env = stubAudioEnv({ resumeSettles: true });
  const c = {};
  mod.setCall(c);
  mod.vcOpenMic(c);
  assert.equal(env.gumCalls, 1, "必须在同步块内调用 getUserMedia，任何先行 await 都会终止用户激活");
  assert.equal(env.ctxCreated, 1);
  assert.ok(c.micP && typeof c.micP.then === "function");
  env.resolveGum(env.stream);
  assert.equal(await c.micP, env.stream);
  await c.resumeP;
  assert.equal(env.stopped, 0, "正常流程不该停掉轨道");
  env.restore();
});
await test("行为：resume() 永不 settle 也不会卡住通话建立", async () => {
  const env = stubAudioEnv({ resumeSettles: false });
  const t0 = Date.now();
  await mod.vcResume(new globalThis.window.AudioContext(), 30);
  assert.ok(Date.now() - t0 < 2000, "必须靠超时返回，而不是等一个永不兑现的 promise");
  const c = {}; mod.setCall(c); mod.vcOpenMic(c);
  assert.equal(env.gumCalls, 1, "resume 卡住时 getUserMedia 仍须已被调用");
  env.resolveGum(env.stream); await c.micP;
  env.restore();
});
await test("行为：授权弹窗期间取消通话，用户随后点「允许」时轨道被立即停掉（麦克风不会一直开着）", async () => {
  const env = stubAudioEnv({ resumeSettles: true });
  const c = {}; mod.setCall(c); mod.vcOpenMic(c);
  c.dead = true;                                   // 相当于 vcCleanAudio 被调用
  env.resolveGum(env.stream);
  await c.micP; await new Promise((r) => setTimeout(r, 0));
  assert.equal(env.stopped, 1, "取消后才授权的流必须停掉");
  const c2 = {}; mod.setCall(c2); mod.vcOpenMic(c2);
  mod.setCall({});                                 // 通话已被别的对象取代
  env.resolveGum(env.stream);
  await c2.micP; await new Promise((r) => setTimeout(r, 0));
  assert.equal(env.stopped, 2, "call 已换人时同样必须停掉");
  env.restore();
});
await test("vcCleanAudio 标记 dead 并回收轨道与点击监听", () => {
  const b = codeOf("vcCleanAudio");
  assert.ok(/c\.dead\s*=\s*true/.test(b));
  assert.ok(/getTracks\(\)\.forEach\(t=>t\.stop\(\)\)/.test(b));
  assert.ok(/removeEventListener\("click"/.test(b));
});

console.log(`\n全部通过：${passed} 项。`);
