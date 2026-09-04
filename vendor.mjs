#!/usr/bin/env node
// 把运行时依赖的两个算法库固定到本地 ./vendor（之后由 server.js 同源提供，CSP 自动移除 esm.sh）：
//   vendor/ml-kem.mjs     ← @noble/post-quantum@0.5.4 的 ml-kem 子模块（单文件 bundle）
//   vendor/hash-wasm.mjs  ← hash-wasm@4.12.0（Argon2id；wasm 以 base64 内嵌，故仍需 CSP 'wasm-unsafe-eval'）
//
// 用法：  npm run vendor           （联网执行一次；建议在两台不同网络的机器上各跑一次、比对 SHA-256）
//         npm run vendor -- --check（只比对 vendor/manifest.json 记录的哈希与现有文件是否一致）
//
// 为什么要固定：浏览器每次打开页面都从 esm.sh 拉取密码学实现，等于把整套安全性托付给 CDN 及
// 通往它的每一跳；本地固定后，运行时不再加载任何第三方代码。请把 vendor/ 目录纳入版本控制。
//
// 这个脚本做的事很朴素：请求 esm.sh 的 ?bundle 版本，跟随它的 `export * from "/..."` 转发壳，
// 直到拿到不再引用外部路径的自包含模块；随后做基本的“像不像 JS 模块”检查并写入 manifest。
// 如果你更信任自己的构建链，也可以用 esbuild 自行打包（结果同样放到 vendor/）：
//   npm i -D esbuild && npm i @noble/post-quantum@0.5.4 hash-wasm@4.12.0
//   npx esbuild node_modules/@noble/post-quantum/ml-kem.js --bundle --format=esm --target=es2022 --outfile=vendor/ml-kem.mjs
//   npx esbuild node_modules/hash-wasm/dist/index.esm.js   --bundle --format=esm --target=es2022 --outfile=vendor/hash-wasm.mjs
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";

const ROOT = path.dirname(fileURLToPath(import.meta.url));
const VENDOR = path.join(ROOT, "vendor");
const MANIFEST = path.join(VENDOR, "manifest.json");
const ORIGIN = "https://esm.sh";
const FILES = [
  { name: "ml-kem.mjs",    url: `${ORIGIN}/@noble/post-quantum@0.5.4/ml-kem?bundle&target=es2022`, mustExport: /ml_kem1024/ },
  { name: "hash-wasm.mjs", url: `${ORIGIN}/hash-wasm@4.12.0?bundle&target=es2022`,                 mustExport: /argon2id/ },
];

const sha256 = (b) => crypto.createHash("sha256").update(b).digest("hex");

async function fetchText(u) {
  const r = await fetch(u, { redirect: "follow", headers: { "user-agent": "pqsession-vendor/2.0" } });
  if (!r.ok) throw new Error(`HTTP ${r.status} ${u}`);
  return { text: await r.text(), finalUrl: r.url || u, esmPath: r.headers.get("x-esm-path") || "" };
}

// 跟随 esm.sh 的转发壳：`export * from "/pkg@ver/es2022/x.mjs"` / `export { default } from ...`
async function resolveBundle(url) {
  let cur = url, hops = 0, last;
  while (hops++ < 5) {
    last = await fetchText(cur);
    const t = last.text;
    const m = t.match(/^\s*(?:export\s+\*\s+from|export\s*\{[^}]*\}\s*from|import\s+[^"']*from)\s*["'](\/[^"']+)["']/m);
    const isShell = t.length < 4096 && m;
    if (!isShell) return { code: t, from: last.finalUrl };
    cur = new URL(m[1], ORIGIN).href;
  }
  throw new Error("转发层级过深：" + url);
}

function sanityCheck(name, code, mustExport) {
  if (code.length < 1000) throw new Error(`${name}: 内容太短，不像模块`);
  if (/^\s*</.test(code)) throw new Error(`${name}: 返回的是 HTML（错误页？）`);
  if (!mustExport.test(code)) throw new Error(`${name}: 未见预期的导出 ${mustExport}`);
  const ext = code.match(/(?:from|import)\s*\(?\s*["'](https?:\/\/[^"']+|\/[^"']+)["']/g);
  if (ext) throw new Error(`${name}: bundle 仍引用外部模块，不是自包含的：${ext.slice(0, 3).join(" ")}`);
}

async function main() {
  const checkOnly = process.argv.includes("--check");
  if (checkOnly) {
    if (!fs.existsSync(MANIFEST)) { console.error("没有 vendor/manifest.json，请先 npm run vendor"); process.exit(1); }
    const man = JSON.parse(fs.readFileSync(MANIFEST, "utf8"));
    let bad = 0;
    for (const f of FILES) {
      const p = path.join(VENDOR, f.name);
      const h = fs.existsSync(p) ? sha256(fs.readFileSync(p)) : "(缺失)";
      const ok = man.files && man.files[f.name] && man.files[f.name].sha256 === h;
      console.log(`${ok ? "OK " : "BAD"} ${f.name}  ${h}`);
      if (!ok) bad++;
    }
    process.exit(bad ? 1 : 0);
  }
  fs.mkdirSync(VENDOR, { recursive: true });
  const manifest = { generatedAt: new Date().toISOString(), files: {} };
  for (const f of FILES) {
    process.stdout.write(`下载 ${f.name} ← ${f.url}\n`);
    const { code, from } = await resolveBundle(f.url);
    sanityCheck(f.name, code, f.mustExport);
    const p = path.join(VENDOR, f.name);
    fs.writeFileSync(p, code);
    const h = sha256(fs.readFileSync(p));
    manifest.files[f.name] = { sha256: h, bytes: code.length, resolvedFrom: from };
    console.log(`  → ${p}  ${code.length} 字节  sha256=${h}`);
  }
  fs.writeFileSync(MANIFEST, JSON.stringify(manifest, null, 2) + "\n");
  console.log("\n已写入 vendor/manifest.json。建议在另一台机器 / 另一条网络上再跑一次并比对上面的 SHA-256，" +
    "两次一致再上线；之后启动 server.js 会自动从 script-src 移除 https://esm.sh。");
}

main().catch((e) => { console.error("失败：" + (e && e.message || e)); process.exit(1); });
