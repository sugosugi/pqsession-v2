#!/usr/bin/env node
// 生成自签名 TLS 证书（ECDSA P-256），让局域网 / 内网部署也能用 https://。
// 浏览器只在安全上下文（https:// 或 localhost）里提供 Web Crypto 与麦克风，
// 用 http://192.168.x.x:8080 访问本页时，生成密钥与语音通话都会失败，这是浏览器的硬性限制。
//
// 用法：  npm run cert                       （SAN 自动包含 localhost、127.0.0.1 与本机所有局域网 IP）
//         npm run cert -- chat.lan 10.0.0.5   （追加额外的域名 / IP）
// 然后：  TLS_CERT=cert.pem TLS_KEY=key.pem npm start
// 浏览器会对自签名证书给出一次警告，选择“继续访问”后该源即被视为安全上下文（麦克风与 Web Crypto 可用）。
// 手机端可把 cert.pem 安装为受信任证书后再访问。
//
// 依赖系统里的 openssl（Linux / macOS / Git for Windows 自带）。
import { spawnSync } from "node:child_process";
import os from "node:os";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.dirname(fileURLToPath(import.meta.url));
const CERT = path.join(ROOT, "cert.pem"), KEY = path.join(ROOT, "key.pem");

const sans = new Set(["DNS:localhost", "IP:127.0.0.1", "IP:::1"]);
for (const list of Object.values(os.networkInterfaces())) {
  for (const ni of list || []) if (ni.family === "IPv4" && !ni.internal) sans.add("IP:" + ni.address);
}
for (const extra of process.argv.slice(2)) sans.add(/^\d+\.\d+\.\d+\.\d+$/.test(extra) ? "IP:" + extra : "DNS:" + extra);

if (fs.existsSync(CERT) || fs.existsSync(KEY)) {
  console.error(`已存在 ${CERT} 或 ${KEY}，不覆盖。要重新生成请先删除它们。`);
  process.exit(1);
}
const v = spawnSync("openssl", ["version"], { encoding: "utf8" });
if (v.status !== 0) {
  console.error("找不到 openssl。请安装后重试，或用 mkcert（https://github.com/FiloSottile/mkcert）生成证书后以 TLS_CERT/TLS_KEY 指定。");
  process.exit(1);
}
const args = ["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
  "-keyout", KEY, "-out", CERT, "-days", "825", "-subj", "/CN=pqsession relay",
  "-addext", "subjectAltName=" + [...sans].join(","),
  "-addext", "keyUsage=digitalSignature,keyEncipherment",
  "-addext", "extendedKeyUsage=serverAuth"];
const r = spawnSync("openssl", args, { stdio: "inherit" });
if (r.status !== 0) { console.error("openssl 执行失败（需要 OpenSSL 1.1.1+ 才支持 -addext）。"); process.exit(1); }
try { fs.chmodSync(KEY, 0o600); } catch {}
console.log(`\n已生成：\n  证书 ${CERT}\n  私钥 ${KEY}（仅本用户可读）\n  SAN  ${[...sans].join(", ")}\n\n启动：TLS_CERT=cert.pem TLS_KEY=key.pem npm start\n` +
  "然后用 https://<本机IP>:8080 访问；浏览器会提示证书不受信任，选择“继续访问”即可。");
