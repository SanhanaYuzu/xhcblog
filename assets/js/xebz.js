/* ============================================================
   XHC XEBZ v1 — XHC 独立加密压缩格式（前端模块）
   与 xebz.py 完全互通（同算法 + 同容器）。

   ★ 格式（XHCBZ v1 · 大端序）★
   0   6   magic "XHCEBZ"
   6   2   version 0x0100
   8   1   kdf: 0=明文 1=PBKDF2-SHA256+AES-256-GCM
   9   4   iterations（kdf=1）
   13  1   salt_len + salt(16)
   30  1   iv_len + iv(12)
   43  8   payload_len
   51  N   payload（kdf=1 加密）

   payload（归档）:
     [entries u32][清单×entries: name_len u32+name+orig_size u64+method u8+crc32 u32]
     [数据块×entries: comp_size u64+comp_data]

   ★ 原创压缩 method=1（XHC-Combo）★
     RLE-X 变换（run token + 0x00/0x02 转义）→ Huffman-256（码长表+位流）
   ============================================================ */
(function (global) {
  'use strict';

  var MAGIC = new Uint8Array([0x58, 0x48, 0x43, 0x45, 0x42, 0x5a]); // "XHCEBZ"
  var VERSION = 0x0100;
  var KDF_NONE = 0, KDF_PBKDF2 = 1;
  var DEFAULT_ITER = 100000;
  var HEADER_LEN = 51;
  var METHOD_STORE = 0, METHOD_COMBO = 1;
  var RUN_MAX = 258;

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

  /* CRC32 */
  var crcTable = null;
  function crc32(bytes) {
    if (!crcTable) {
      crcTable = new Int32Array(256);
      for (var i = 0; i < 256; i++) {
        var c = i;
        for (var j = 0; j < 8; j++) c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
        crcTable[i] = c;
      }
    }
    var crc = -1;
    for (var k = 0; k < bytes.length; k++) crc = (crc >>> 8) ^ crcTable[(crc ^ bytes[k]) & 0xFF];
    return (crc ^ -1) >>> 0;
  }

  /* ---------- RLE-X ---------- */
  function rleCompress(data) {
    var out = [], i = 0, n = data.length;
    while (i < n) {
      var j = i + 1;
      while (j < n && data[j] === data[i] && j - i < RUN_MAX) j++;
      var run = j - i;
      if (run >= 4) {
        out.push(0x02, run - 4, data[i]);
        i = j;
      } else {
        var b = data[i];
        if (b === 0x00 || b === 0x02) out.push(0x00, b);
        else out.push(b);
        i++;
      }
    }
    return new Uint8Array(out);
  }
  function rleDecompress(tokens) {
    var out = [], i = 0, n = tokens.length;
    while (i < n) {
      var t = tokens[i];
      if (t === 0x00) { out.push(tokens[i + 1]); i += 2; }
      else if (t === 0x02) {
        var run = tokens[i + 1] + 4, b = tokens[i + 2];
        while (run--) out.push(b);
        i += 3;
      } else { out.push(t); i++; }
    }
    return new Uint8Array(out);
  }

  /* ---------- Huffman-256 ---------- */
  function huffmanLens(freq) {
    var heap = [];
    for (var i = 0; i < 256; i++) if (freq[i] > 0) heap.push([freq[i], i]);
    if (!heap.length) return new Uint8Array(256);
    heap.sort(function (a, b) { return a[0] - b[0]; });
    var counter = 0;
    function push(f, node) { heap.push([f, node]); counter++; }
    function pop() { heap.sort(function (a, b) { return a[0] - b[0]; }); return heap.shift()[1]; }
    while (heap.length > 1) {
      var n1 = pop(), n2 = pop();
      push(freqOf(n1) + freqOf(n2), [n1, n2]);
    }
    function freqOf(node) {
      if (node instanceof Array) { return freqOf(node[0]) + freqOf(node[1]); }
      return freq[node];
    }
    var root = heap[0][1];
    var lens = new Uint8Array(256);
    function walk(node, depth) {
      if (node instanceof Array) { walk(node[0], depth + 1); walk(node[1], depth + 1); }
      else lens[node] = depth;
    }
    walk(root, 0);
    return lens;
  }
  function canonicalCodes(lens) {
    var syms = [];
    for (var i = 0; i < 256; i++) if (lens[i] > 0) syms.push(i);
    syms.sort(function (a, b) { return lens[a] - lens[b] || a - b; });
    var codes = {}, code = 0, prev = 0;
    for (var k = 0; k < syms.length; k++) {
      var s = syms[k];
      if (lens[s] > prev) code <<= (lens[s] - prev);
      codes[s] = code;
      code++;
      prev = lens[s];
    }
    return codes;
  }
  function huffmanEncode(data) {
    var freq = new Uint32Array(256);
    for (var i = 0; i < data.length; i++) freq[data[i]]++;
    var lens = huffmanLens(freq);
    var codes = canonicalCodes(lens);
    var out = [];
    for (var j = 0; j < 256; j++) out.push(lens[j]);
    var symCount = data.length;
    out.push((symCount >>> 24) & 255, (symCount >>> 16) & 255, (symCount >>> 8) & 255, symCount & 255);
    var bits = [], cur = 0, nbits = 0;
    function put(code, l) {
      for (var x = l - 1; x >= 0; x--) {
        cur = (cur << 1) | ((code >> x) & 1);
        nbits++;
        if (nbits === 8) { bits.push(cur); cur = 0; nbits = 0; }
      }
    }
    for (var m = 0; m < data.length; m++) put(codes[data[m]], lens[data[m]]);
    if (nbits) { cur <<= (8 - nbits); bits.push(cur); }
    return concatBytes(new Uint8Array(out), new Uint8Array(bits));
  }
  function huffmanDecode(data) {
    var lens = data.subarray(0, 256);
    var codes = canonicalCodes(lens);
    var byLen = {}, maxLen = 0;
    for (var s = 0; s < 256; s++) {
      if (lens[s] > 0) {
        if (!byLen[lens[s]]) byLen[lens[s]] = {};
        byLen[lens[s]][codes[s]] = s;
        if (lens[s] > maxLen) maxLen = lens[s];
      }
    }
    var symCount = readU32(data, 256);
    var pos = 260, cur = 0, n = 0;
    function bit() {
      if (n === 0) { cur = data[pos]; pos++; n = 8; }
      var b = (cur >> 7) & 1;
      cur = (cur << 1) & 255;
      n--;
      return b;
    }
    var out = [];
    for (var c2 = 0; c2 < symCount; c2++) {
      var code = 0, got = false;
      for (var l = 1; l <= maxLen; l++) {
        code = (code << 1) | bit();
        if (byLen[l] && byLen[l][code] !== undefined) { out.push(byLen[l][code]); got = true; break; }
      }
      if (!got) break;
    }
    return new Uint8Array(out);
  }

  /* ---------- Combo ---------- */
  function comboCompress(data) { return huffmanEncode(rleCompress(data)); }
  function comboDecompress(data) { return rleDecompress(huffmanDecode(data)); }

  /* ---------- 加密 ---------- */
  function assertCrypto() {
    if (!global.crypto || !global.crypto.subtle) throw new Error('当前环境不支持 Web Crypto API');
  }
  async function deriveKey(password, salt, iterations) {
    var base = await crypto.subtle.importKey('raw', te.encode(password), 'PBKDF2', false, ['deriveBits']);
    var bits = await crypto.subtle.deriveBits(
      { name: 'PBKDF2', salt: salt, iterations: iterations, hash: 'SHA-256' }, base, 256);
    return crypto.subtle.importKey('raw', bits, 'AES-GCM', false, ['encrypt', 'decrypt']);
  }

  /* ---------- pack / unpack ---------- */
  async function pack(files, password) {
    /* files: [{name, data: Uint8Array}] → Uint8Array(.xebz) */
    assertCrypto();
    var pl = [], i;
    pl.push.apply(pl, u32be(files.length));
    var blocks = [];
    for (i = 0; i < files.length; i++) {
      var f = files[i];
      var nb = te.encode(f.name);
      var crc = crc32(f.data);
      var comp = comboCompress(f.data);
      var use, block;
      if (comp.length < f.data.length) { use = METHOD_COMBO; block = comp; }
      else { use = METHOD_STORE; block = f.data; }
      pl.push.apply(pl, u32be(nb.length));
      pl.push.apply(pl, nb);
      pl.push.apply(pl, u64be(f.data.length));
      pl.push(use);
      pl.push.apply(pl, u32be(crc));
      blocks.push(block);
    }
    for (i = 0; i < blocks.length; i++) {
      pl.push.apply(pl, u64be(blocks[i].length));
      pl.push.apply(pl, blocks[i]);
    }
    var payloadPlain = new Uint8Array(pl);

    var kdf = KDF_NONE, salt = new Uint8Array(16), iv = new Uint8Array(12), iters = 0, payload = payloadPlain;
    if (password) {
      kdf = KDF_PBKDF2;
      iters = DEFAULT_ITER;
      salt = crypto.getRandomValues(new Uint8Array(16));
      iv = crypto.getRandomValues(new Uint8Array(12));
      var key = await deriveKey(String(password), salt, iters);
      payload = new Uint8Array(await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: iv, tagLength: 128 }, key, payloadPlain));
    }
    var head = [];
    head.push.apply(head, MAGIC);
    head.push.apply(head, u16be(VERSION));
    head.push(kdf);
    head.push.apply(head, u32be(iters));
    head.push(salt.length);
    head.push.apply(head, salt);
    head.push(iv.length);
    head.push.apply(head, iv);
    head.push.apply(head, u64be(payload.length));
    return concatBytes(new Uint8Array(head), payload);
  }

  async function unpack(bytes, password) {
    /* → [{name, data: Uint8Array}]（校验 crc32） */
    assertCrypto();
    var u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
    if (u8.length < HEADER_LEN) throw new Error('文件过短，不是有效的 XEBZ');
    for (var i = 0; i < 6; i++) if (u8[i] !== MAGIC[i]) throw new Error('不是有效的 XEBZ 文件（magic 不符）');
    var ver = readU16(u8, 6);
    if ((ver >> 8) !== 1) throw new Error('不支持的版本: 0x' + ver.toString(16));
    var kdf = u8[8];
    var iters = readU32(u8, 9);
    var saltLen = u8[13], ivLen = u8[30];
    var salt = u8.subarray(14, 14 + saltLen);
    var iv = u8.subarray(31, 31 + ivLen);
    var plen = readU64(u8, 43);
    var payload = u8.subarray(51, 51 + plen);
    var plain;
    if (kdf === KDF_PBKDF2) {
      if (!password) throw new Error('该文件已加密，需要密码');
      var key = await deriveKey(String(password), salt, iters);
      try {
        plain = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv, tagLength: 128 }, key, payload));
      } catch (e) { throw new Error('解密失败：密码错误或文件已损坏'); }
    } else if (kdf === KDF_NONE) {
      if (password) throw new Error('该文件未加密，无需密码');
      plain = payload;
    } else throw new Error('不支持的 KDF: ' + kdf);

    var off = 0;
    var entries = readU32(plain, off); off += 4;
    var headers = [], blockLens = [];
    for (i = 0; i < entries; i++) {
      var nameLen = readU32(plain, off); off += 4;
      var name = td.decode(plain.subarray(off, off + nameLen)); off += nameLen;
      var origSize = readU64(plain, off); off += 8;
      var method = plain[off]; off += 1;
      var crc = readU32(plain, off); off += 4;
      headers.push({ name: name, origSize: origSize, method: method, crc32: crc });
    }
    var blocks = [];
    for (i = 0; i < entries; i++) {
      var compSize = readU64(plain, off); off += 8;
      blocks.push(plain.subarray(off, off + compSize));
      off += compSize;
    }
    var out = [];
    for (i = 0; i < entries; i++) {
      var data;
      if (headers[i].method === METHOD_COMBO) data = comboDecompress(blocks[i]);
      else if (headers[i].method === METHOD_STORE) data = blocks[i];
      else throw new Error('不支持的压缩方法: ' + headers[i].method);
      if (crc32(data) !== headers[i].crc32) throw new Error('校验失败（数据损坏?）: ' + headers[i].name);
      out.push({ name: headers[i].name, data: data });
    }
    return out;
  }

  global.XEBZ = {
    VERSION: '1.0.0',
    FORMAT: 'XHCBZ-v1',
    pack: pack,
    unpack: unpack,
    comboCompress: comboCompress,
    comboDecompress: comboDecompress
  };
})(typeof window !== 'undefined' ? window : (typeof globalThis !== 'undefined' ? globalThis : this));
