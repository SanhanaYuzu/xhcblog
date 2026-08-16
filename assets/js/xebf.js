/* ============================================================
   XHC XEBF v1 — XHC 加密博客文章格式（前端转码模块）
   与 xebf.py 完全互通（二进制格式一致）。

   ★ 文件格式（二进制，大端序）★
   偏移    长度    字段
   0       6      magic: "XHCEBF"
   6       2      version: uint16 = 0x0100
   8       1      kdf: uint8 = 1 (PBKDF2-HMAC-SHA256)
   9       4      iterations: uint32 = 100000
   13      1      salt_len: uint8 = 16
   14      16     salt
   30      1      iv_len: uint8 = 12
   31      12     iv (AES-GCM)
   43      8      payload_len: uint64
   51      N      payload: AES-256-GCM 密文(含 16 字节认证 tag)

   ★ 负载明文（JSON UTF-8）★
   {
     "type": "xhc-blog-article",
     "version": 1,
     "meta": { title, summary, category, tags[], cover, series,
               scheduled_at, created_at, updated_at },
     "content": "HTML/Markdown 正文",
     "content_type": "html" | "markdown"
   }

   ★ 安全说明 ★
   - AES-256-GCM：认证加密（AEAD），密文被篡改/密码错误 → 解密抛错
   - PBKDF2-HMAC-SHA256 10 万次迭代：抗暴力破解
   - salt / iv 每次随机，随文件保存，可安全复用密码
   - 前端用 Web Crypto API（所有现代浏览器内置）
   ============================================================ */
(function (global) {
  'use strict';

  var MAGIC = new Uint8Array([0x58, 0x48, 0x43, 0x45, 0x42, 0x46]); // "XHCEBF"
  var VERSION = 0x0100;
  var KDF_PBKDF2_SHA256 = 1;
  var DEFAULT_ITER = 100000;
  var HEADER_LEN = 51;

  var te = new TextEncoder();
  var td = new TextDecoder();

  function concatBytes() {
    var arr = Array.prototype.slice.call(arguments), total = 0, i, out, p = 0;
    for (i = 0; i < arr.length; i++) total += arr[i].length;
    out = new Uint8Array(total);
    for (i = 0; i < arr.length; i++) { out.set(arr[i], p); p += arr[i].length; }
    return out;
  }
  function u16be(n) { return new Uint8Array([(n >> 8) & 255, n & 255]); }
  function u32be(n) { return new Uint8Array([(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255]); }
  function u64be(n) {
    var hi, lo;
    if (typeof n === 'bigint') { hi = Number(n >> 32n) >>> 0; lo = Number(n & 0xffffffffn) >>> 0; }
    else { hi = Math.floor(n / 4294967296) >>> 0; lo = n >>> 0; }
    return new Uint8Array([(hi >>> 24) & 255, (hi >>> 16) & 255, (hi >>> 8) & 255, hi & 255, (lo >>> 24) & 255, (lo >>> 16) & 255, (lo >>> 8) & 255, lo & 255]);
  }
  function readU16(u8, o) { return ((u8[o] << 8) | u8[o + 1]) & 0xffff; }
  function readU32(u8, o) { return (((u8[o] << 24) | (u8[o + 1] << 16) | (u8[o + 2] << 8) | u8[o + 3])) >>> 0; }
  function readU64(u8, o) { var hi = readU32(u8, o), lo = readU32(u8, o + 4); return hi * 4294967296 + lo; }

  function assertCrypto() {
    if (!global.crypto || !global.crypto.subtle) {
      throw new Error('当前环境不支持 Web Crypto API（需要 HTTPS 或 localhost）');
    }
  }

  async function deriveKey(password, salt, iterations) {
    var base = await crypto.subtle.importKey('raw', te.encode(password), 'PBKDF2', false, ['deriveBits']);
    var bits = await crypto.subtle.deriveBits(
      { name: 'PBKDF2', salt: salt, iterations: iterations, hash: 'SHA-256' },
      base, 256
    );
    return crypto.subtle.importKey('raw', bits, 'AES-GCM', false, ['encrypt', 'decrypt']);
  }

  /** 加密文章对象为 .xebf 二进制（Uint8Array） */
  async function encode(article, password, iterations) {
    assertCrypto();
    iterations = iterations || DEFAULT_ITER;
    var plain = te.encode(JSON.stringify(article));
    var salt = crypto.getRandomValues(new Uint8Array(16));
    var iv = crypto.getRandomValues(new Uint8Array(12));
    var key = await deriveKey(String(password), salt, iterations);
    var ct = new Uint8Array(await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: iv, tagLength: 128 }, key, plain));
    return concatBytes(
      MAGIC, u16be(VERSION), new Uint8Array([KDF_PBKDF2_SHA256]), u32be(iterations),
      new Uint8Array([salt.length]), salt,
      new Uint8Array([iv.length]), iv,
      u64be(ct.length), ct
    );
  }

  /** 解密 .xebf 二进制为文章对象（密码错误/损坏 → throw） */
  async function decode(bytes, password) {
    assertCrypto();
    var u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
    if (u8.length < HEADER_LEN) throw new Error('文件过短，不是有效的 XEBF');
    for (var i = 0; i < 6; i++) if (u8[i] !== MAGIC[i]) throw new Error('不是有效的 XEBF 文件（magic 不符）');
    var ver = readU16(u8, 6);
    if (((ver >> 8) & 0xff) !== 1) throw new Error('不支持的版本: 0x' + ver.toString(16));
    var kdf = u8[8];
    if (kdf !== KDF_PBKDF2_SHA256) throw new Error('不支持的 KDF 类型: ' + kdf);
    var iter = readU32(u8, 9);
    var saltLen = u8[13], ivLen = u8[30];
    var salt = u8.slice(14, 14 + saltLen);
    var iv = u8.slice(31, 31 + ivLen);
    var plen = readU64(u8, 43);
    var ct = u8.slice(51, 51 + plen);
    var key = await deriveKey(String(password), salt, iter);
    var plain;
    try {
      plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv, tagLength: 128 }, key, ct);
    } catch (e) {
      throw new Error('解密失败：密码错误或文件已损坏');
    }
    return JSON.parse(td.decode(plain));
  }

  /** 便捷：加密为 base64 字符串（适合粘贴/文本传输） */
  async function encodeB64(article, password, iterations) {
    var b = await encode(article, password, iterations);
    var s = '', chunk = 8192, i;
    for (i = 0; i < b.length; i += chunk) {
      s += String.fromCharCode.apply(null, b.subarray(i, i + chunk));
    }
    return btoa(s);
  }

  /** 便捷：从 base64 解密 */
  async function decodeB64(b64, password) {
    var bin = atob(b64);
    var u8 = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i);
    return decode(u8, password);
  }

  var api = {
    VERSION: '1.0.0',
    FORMAT: 'XHCEBF-v1',
    DEFAULT_ITERATIONS: DEFAULT_ITER,
    encode: encode,
    decode: decode,
    encodeB64: encodeB64,
    decodeB64: decodeB64
  };
  global.XEBF = api;
})(typeof window !== 'undefined' ? window : (typeof globalThis !== 'undefined' ? globalThis : this));
