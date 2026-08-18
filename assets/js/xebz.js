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
  var VERSION = 0x020A;  // 2.10 XHCZ8（x8 单流=4MB-LZ+z7 四模型 CM；x8auto=min(x8,adapt,store)，构造性优于 XHCZ7；读取兼容 1.x~2.9）
  var KDF_NONE = 0, KDF_PBKDF2 = 1, KDF_ARGON2 = 2, KDF_COMBO3 = 3;
  var CIPHER_CHACHA20 = 1, CIPHER_DUAL = 2;
  var DEFAULT_ITER = 100000;
  var HEADER_LEN = 51;
  var METHOD_STORE = 0, METHOD_COMBO = 1, METHOD_Z2 = 2, METHOD_Z3 = 3, METHOD_Z4 = 4, METHOD_Z5 = 5, METHOD_Z6 = 6, METHOD_SS = 7, METHOD_PRO = 8, METHOD_OPTIMA = 9, METHOD_Z7 = 10, METHOD_ADAPT = 11, METHOD_Z8 = 12, METHOD_X8AUTO = 13;
  var OPTIMA_BLOCK = 1048576;
  var OPTIMA_MODE_SS = 0, OPTIMA_MODE_PRO = 1, OPTIMA_MODE_STORE = 2, OPTIMA_MODE_Z4 = 3, OPTIMA_MODE_Z6 = 4, OPTIMA_MODE_Z3 = 5;
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

  /* ---------- XHCZ2-LZ（自研哈希链匹配器） ---------- */
  var TOKEN_ESC = 0x00, TOKEN_MATCH = 0x01, TOKEN_RUN = 0x02;
  var Z2_WINDOW = 32768, Z2_MIN = 4, Z2_MAX = 258;

  function z2LzCompress(data) {
    var n = data.length, out = [], i = 0, chain = new Map();
    while (i < n) {
      var bestLen = 0, bestOff = 0;
      if (i + 3 <= n) {
        var h = (data[i] << 16) | (data[i + 1] << 8) | data[i + 2];
        var last = chain.has(h) ? chain.get(h) : -1;
        if (last >= 0 && i - last <= Z2_WINDOW) {
          var m = 0;
          while (m < Z2_MAX && i + m < n && data[last + m] === data[i + m]) m++;
          if (m >= Z2_MIN) { bestLen = m; bestOff = i - last; }
        }
      }
      if (bestLen >= Z2_MIN) {
        out.push(TOKEN_MATCH, (bestOff >> 8) & 255, bestOff & 255, Math.min(bestLen, Z2_MAX) - Z2_MIN);
        for (var k = 0; k < bestLen; k++)
          if (i + k + 3 <= n) chain.set((data[i+k]<<16)|(data[i+k+1]<<8)|data[i+k+2], i + k);
        i += bestLen;
      } else {
        var j = i + 1;
        while (j < n && data[j] === data[i] && j - i < Z2_MAX) j++;
        if (j - i >= Z2_MIN) {
          out.push(TOKEN_RUN, (j - i) - Z2_MIN, data[i]);
          for (var k2 = 0; k2 < j - i; k2++)
            if (i + k2 + 3 <= n) chain.set((data[i+k2]<<16)|(data[i+k2+1]<<8)|data[i+k2+2], i + k2);
          i = j;
        } else {
          var b = data[i];
          if (b === TOKEN_ESC || b === TOKEN_MATCH || b === TOKEN_RUN) out.push(TOKEN_ESC, b);
          else out.push(b);
          if (i + 3 <= n) chain.set((data[i]<<16)|(data[i+1]<<8)|data[i+2], i);
          i++;
        }
      }
    }
    return new Uint8Array(out);
  }

  function z2LzDecompress(tokens) {
    var out = [], i = 0, n = tokens.length;
    while (i < n) {
      var t = tokens[i];
      if (t === TOKEN_ESC) { out.push(tokens[i + 1]); i += 2; }
      else if (t === TOKEN_MATCH) {
        var off = (tokens[i + 1] << 8) | tokens[i + 2];
        var ln = tokens[i + 3] + Z2_MIN;
        var src = out.length - off;
        for (var k = 0; k < ln; k++) { out.push(out[src]); src++; }
        i += 4;
      } else if (t === TOKEN_RUN) {
        var rl = tokens[i + 1] + Z2_MIN;
        for (var m2 = 0; m2 < rl; m2++) out.push(tokens[i + 2]);
        i += 3;
      } else { out.push(t); i++; }
    }
    return new Uint8Array(out);
  }

  /* ---------- XHCZ2-ACE（自研 32-bit 整数算术编码） ---------- */
  function z2Freq(data) {
    var freq = new Uint32Array(256);
    for (var i = 0; i < data.length; i++) freq[data[i]]++;
    for (var j = 0; j < 256; j++) if (freq[j] === 0) freq[j] = 1;
    return freq;
  }
  function z2Cum(freq) {
    var cum = new Uint32Array(257), s = 0;
    for (var i = 0; i < 256; i++) { cum[i + 1] = cum[i] + freq[i]; }
    return { cum: cum, total: cum[256] };
  }

  function z2AceEncode(data) {
    var freq = z2Freq(data), ct = z2Cum(freq), cum = ct.cum, total = ct.total;
    var out = [];
    for (var f = 0; f < 256; f++) out.push.apply(out, u32be(freq[f]));
    out.push.apply(out, u32be(data.length));
    var MASK = 0xFFFFFFFF, HALF = 0x80000000, QTR1 = 0x40000000, QTR3 = 0xC0000000;
    var low = 0, high = MASK, pending = 0, bits = [];
    function bpf(b) { // bit_plus_follow
      bits.push(b);
      while (pending > 0) { bits.push(b ^ 1); pending--; }
    }
    for (var i = 0; i < data.length; i++) {
      var sym = data[i];
      var rng = high - low + 1;
      var hh = Math.floor((rng * cum[sym + 1]) / total);
      var ll = Math.floor((rng * cum[sym]) / total);
      high = (low + hh - 1) >>> 0;
      low = (low + ll) >>> 0;
      for (;;) {
        if (high < HALF) {
          bpf(0);
          low = (low << 1) >>> 0; high = ((high << 1) | 1) >>> 0;
        } else if (low >= HALF) {
          bpf(1);
          low = (low - HALF) >>> 0; high = (high - HALF) >>> 0;
          low = (low << 1) >>> 0; high = ((high << 1) | 1) >>> 0;
        } else if (low >= QTR1 && high < QTR3) {
          pending++;
          low = (low - QTR1) >>> 0; high = (high - QTR1) >>> 0;
          low = (low << 1) >>> 0; high = ((high << 1) | 1) >>> 0;
        } else break;
      }
    }
    pending += 1;
    if (low < QTR1) bpf(0); else bpf(1);
    while (bits.length % 8) bits.push(0);
    for (var k = 0; k < bits.length; k += 8) {
      var bb = 0;
      for (var j = 0; j < 8; j++) bb = (bb << 1) | bits[k + j];
      out.push(bb);
    }
    return new Uint8Array(out);
  }

  function z2AceDecode(data, origSize) {
    var freq = new Uint32Array(256);
    for (var i = 0; i < 256; i++) freq[i] = readU32(data, i * 4);
    var ct = z2Cum(freq), cum = ct.cum, total = ct.total;
    var cnt = readU32(data, 1024);
    var pos = 1028, cur = 0, n = 0, limit = data.length;
    function nbit() {
      if (n === 0) {
        if (pos >= limit) return 0;
        cur = data[pos]; pos++; n = 8;
      }
      var b = (cur >> 7) & 1;
      cur = (cur << 1) & 255; n--;
      return b;
    }
    var MASK = 0xFFFFFFFF, HALF = 0x80000000, QTR1 = 0x40000000, QTR3 = 0xC0000000;
    var low = 0, high = MASK, value = 0;
    for (var k = 0; k < 32; k++) value = ((value << 1) | nbit()) >>> 0;
    var out = [];
    for (var s = 0; s < cnt; s++) {
      var rng = high - low + 1;
      var target = Math.floor(((value - low + 1) * total - 1) / rng);
      var lo = 0, hi = 256;
      while (lo < hi) {
        var mid = (lo + hi) >> 1;
        if (cum[mid + 1] <= target) lo = mid + 1; else hi = mid;
      }
      var sym = lo > 255 ? 255 : lo;
      out.push(sym);
      high = (low + Math.floor((rng * cum[sym + 1]) / total) - 1) >>> 0;
      low = (low + Math.floor((rng * cum[sym]) / total)) >>> 0;
      for (;;) {
        if (high < HALF) { /* pass */ }
        else if (low >= HALF) { value = (value - HALF) >>> 0; low = (low - HALF) >>> 0; high = (high - HALF) >>> 0; }
        else if (low >= QTR1 && high < QTR3) { value = (value - QTR1) >>> 0; low = (low - QTR1) >>> 0; high = (high - QTR1) >>> 0; }
        else break;
        low = (low << 1) >>> 0; high = ((high << 1) | 1) >>> 0;
        value = ((value << 1) | nbit()) >>> 0;
      }
    }
    return new Uint8Array(out);
  }

  function z2Compress(data) { return z2AceEncode(z2LzCompress(data)); }
  function z2Decompress(data) { return z2LzDecompress(z2AceDecode(data, 0)); }

  /* ---------- XHCZ3（2.1 RAR5 级增强：1MB 窗口 + lazy + 距离分层 + 分块自适应） ---------- */
  var Z3_WINDOW = 1 << 20, Z3_BLOCK = 65536, Z8_WINDOW = 4 << 20;
  var TOKEN_MATCH_EXT = 0x03;

  function z3LzCompress(data) {
    var n = data.length, out = [], i = 0, chain = new Map();
    function h3(p) { return (data[p] << 16) | (data[p + 1] << 8) | data[p + 2]; }
    function findMatch(pos) {
      if (pos + 3 > n) return [0, 0];
      var last = chain.has(h3(pos)) ? chain.get(h3(pos)) : -1;
      if (last < 0 || pos - last > Z3_WINDOW) return [0, 0];
      var m = 0;
      while (m < 258 && pos + m < n && data[last + m] === data[pos + m]) m++;
      if (m < 4) return [0, 0];
      return [m, pos - last];
    }
    while (i < n) {
      var r = findMatch(i), bl = r[0], bo = r[1];
      if (bl >= 4) {
        if (i + 4 <= n) {
          var r2 = findMatch(i + 1);
          if (r2[0] > bl + 1) {
            var b = data[i];
            if (b === 0x00 || b === 0x01 || b === 0x02 || b === TOKEN_MATCH_EXT) out.push(0x00, b);
            else out.push(b);
            if (i + 3 <= n) chain.set(h3(i), i);
            i++;
            continue;
          }
        }
        if (bo <= 0xFFFF) {
          out.push(0x01, (bo >> 8) & 255, bo & 255, Math.min(bl, 258) - 4);
        } else {
          out.push(TOKEN_MATCH_EXT, (bo >> 16) & 255, (bo >> 8) & 255, bo & 255, Math.min(bl, 258) - 4);
        }
        for (var k = 0; k < bl; k++)
          if (i + k + 3 <= n) chain.set(h3(i + k), i + k);
        i += bl;
      } else {
        var j = i + 1;
        while (j < n && data[j] === data[i] && j - i < 258) j++;
        if (j - i >= 4) {
          out.push(0x02, (j - i) - 4, data[i]);
          for (var k2 = 0; k2 < j - i; k2++)
            if (i + k2 + 3 <= n) chain.set(h3(i + k2), i + k2);
          i = j;
        } else {
          var b2 = data[i];
          if (b2 === 0x00 || b2 === 0x01 || b2 === 0x02 || b2 === TOKEN_MATCH_EXT) out.push(0x00, b2);
          else out.push(b2);
          if (i + 3 <= n) chain.set(h3(i), i);
          i++;
        }
      }
    }
    return new Uint8Array(out);
  }

  function z3LzDecompress(tokens) {
    var out = [], i = 0, n = tokens.length;
    while (i < n) {
      var t = tokens[i];
      if (t === 0x00) { out.push(tokens[i + 1]); i += 2; }
      else if (t === 0x01) {
        var off = (tokens[i + 1] << 8) | tokens[i + 2];
        var ln = tokens[i + 3] + 4;
        var src = out.length - off;
        for (var k = 0; k < ln; k++) { out.push(out[src]); src++; }
        i += 4;
      } else if (t === TOKEN_MATCH_EXT) {
        var off2 = (tokens[i + 1] << 16) | (tokens[i + 2] << 8) | tokens[i + 3];
        var ln2 = tokens[i + 4] + 4;
        var src2 = out.length - off2;
        for (var m2 = 0; m2 < ln2; m2++) { out.push(out[src2]); src2++; }
        i += 5;
      } else if (t === 0x02) {
        var rl = tokens[i + 1] + 4;
        for (var m3 = 0; m3 < rl; m3++) out.push(tokens[i + 2]);
        i += 3;
      }       else { out.push(t); i++; }
    }
    return new Uint8Array(out);
  }

  // XHCZ8（XEBZ 2.10）：4MB 窗口强 LZ 预变换（z3_lz 的超集，仅窗口不同），供 x8 单流复用
  function z8LzCompress(data) {
    var n = data.length, out = [], i = 0, chain = new Map();
    function h3(p) { return (data[p] << 16) | (data[p + 1] << 8) | data[p + 2]; }
    function findMatch(pos) {
      if (pos + 3 > n) return [0, 0];
      var last = chain.has(h3(pos)) ? chain.get(h3(pos)) : -1;
      if (last < 0 || pos - last > Z8_WINDOW) return [0, 0];
      var m = 0;
      while (m < 258 && pos + m < n && data[last + m] === data[pos + m]) m++;
      if (m < 4) return [0, 0];
      return [m, pos - last];
    }
    while (i < n) {
      var r = findMatch(i), bl = r[0], bo = r[1];
      if (bl >= 4) {
        if (i + 4 <= n) {
          var r2 = findMatch(i + 1);
          if (r2[0] > bl + 1) {
            var b = data[i];
            if (b === 0x00 || b === 0x01 || b === 0x02 || b === TOKEN_MATCH_EXT) out.push(0x00, b);
            else out.push(b);
            if (i + 3 <= n) chain.set(h3(i), i);
            i++;
            continue;
          }
        }
        if (bo <= 0xFFFF) {
          out.push(0x01, (bo >> 8) & 255, bo & 255, Math.min(bl, 258) - 4);
        } else {
          out.push(TOKEN_MATCH_EXT, (bo >> 16) & 255, (bo >> 8) & 255, bo & 255, Math.min(bl, 258) - 4);
        }
        for (var k = 0; k < bl; k++)
          if (i + k + 3 <= n) chain.set(h3(i + k), i + k);
        i += bl;
      } else {
        var j = i + 1;
        while (j < n && data[j] === data[i] && j - i < 258) j++;
        if (j - i >= 4) {
          out.push(0x02, (j - i) - 4, data[i]);
          for (var k2 = 0; k2 < j - i; k2++)
            if (i + k2 + 3 <= n) chain.set(h3(i + k2), i + k2);
          i = j;
        } else {
          var b2 = data[i];
          if (b2 === 0x00 || b2 === 0x01 || b2 === 0x02 || b2 === TOKEN_MATCH_EXT) out.push(0x00, b2);
          else out.push(b2);
          if (i + 3 <= n) chain.set(h3(i), i);
          i++;
        }
      }
    }
    return new Uint8Array(out);
  }

  function z3BlocksEncode(tokens) {
    var out = [];
    for (var s = 0; s < tokens.length; s += Z3_BLOCK) {
      var block = tokens.subarray(s, Math.min(s + Z3_BLOCK, tokens.length));
      var enc = z2AceEncode(block);   // [freq 1024][u32 符号数][位流]
      var symCount = readU32(enc, 1024);
      var bits = enc.subarray(1028);
      out.push.apply(out, u32be(symCount));
      out.push.apply(out, u32be(bits.length));
      out.push.apply(out, Array.from(enc.subarray(0, 1024)));
      out.push.apply(out, Array.from(bits));
    }
    return new Uint8Array(out);
  }

  function z3BlocksDecode(data) {
    var out = [], pos = 0;
    while (pos < data.length) {
      var symCount = readU32(data, pos);
      var bitsLen = readU32(data, pos + 4);
      pos += 8;
      var freq = data.subarray(pos, pos + 1024);
      pos += 1024;
      var bits = data.subarray(pos, pos + bitsLen);
      pos += bitsLen;
      var enc = new Uint8Array(1024 + 4 + bitsLen);
      enc.set(freq, 0);
      enc.set(u32be(symCount), 1024);
      enc.set(bits, 1028);
      out.push.apply(out, Array.from(z2AceDecode(enc, 0)));
    }
    return new Uint8Array(out);
  }

  function z3Compress(data) { return z3BlocksEncode(z3LzCompress(data)); }
  function z3Decompress(data) { return z3LzDecompress(z3BlocksDecode(data)); }

  /* ---------- XHCZ4（2.2 7z/LZMA 级增强：自适应二进制算术编码 + 动态概率） ---------- */
  var Z4_HALF = 0x80000000, Z4_QTR1 = 0x40000000, Z4_QTR3 = 0xC0000000, Z4_MASK = 0xFFFFFFFF;
  function z4Encode(data) {
    var probs = new Uint32Array(32).fill(1024);
    var low = 0, high = Z4_MASK, pending = 0, bits = [], prevCtx = 0;
    function bpf(b) {
      bits.push(b);
      while (pending > 0) { bits.push(b ^ 1); pending--; }
    }
    for (var i = 0; i < data.length; i++) {
      var byte = data[i], base = prevCtx * 8;
      for (var bp = 0; bp < 8; bp++) {
        var bit = (byte >> (7 - bp)) & 1, idx = base + bp, p = probs[idx];
        var rng = high - low + 1;
        var mid = (low + Math.floor(rng * p / 2048)) >>> 0;
        if (bit === 0) { high = (mid - 1) >>> 0; probs[idx] = (p + ((2048 - p) >> 5)) >>> 0; }
        else { low = mid; probs[idx] = (p - (p >> 5)) >>> 0; }
        for (;;) {
          if (high < Z4_HALF) { bpf(0); low = (low << 1) >>> 0; high = ((high << 1) | 1) >>> 0; }
          else if (low >= Z4_HALF) { bpf(1); low = (low - Z4_HALF) >>> 0; high = (high - Z4_HALF) >>> 0; low = (low << 1) >>> 0; high = ((high << 1) | 1) >>> 0; }
          else if (low >= Z4_QTR1 && high < Z4_QTR3) { pending++; low = (low - Z4_QTR1) >>> 0; high = (high - Z4_QTR1) >>> 0; low = (low << 1) >>> 0; high = ((high << 1) | 1) >>> 0; }
          else break;
        }
      }
      if (byte === 0) prevCtx = 3;
      else if (byte === 1 || byte === 3) prevCtx = 1;
      else if (byte === 2) prevCtx = 2;
      else prevCtx = 0;
    }
    pending += 1;
    if (low < Z4_QTR1) bpf(0); else bpf(1);
    while (bits.length % 8) bits.push(0);
    var out = [];
    for (var k = 0; k < bits.length; k += 8) {
      var bb = 0;
      for (var j = 0; j < 8; j++) bb = (bb << 1) | bits[k + j];
      out.push(bb);
    }
    return new Uint8Array(out);
  }
  function z4Decode(data) {
    var probs = new Uint32Array(32).fill(1024);
    var cnt = readU32(data, 0);
    var pos = 4, cur = 0, n = 0, limit = data.length, prevCtx = 0;
    function nbit() {
      if (n === 0) { if (pos >= limit) return 0; cur = data[pos]; pos++; n = 8; }
      var b = (cur >> 7) & 1; cur = (cur << 1) & 255; n--; return b;
    }
    var low = 0, high = Z4_MASK, value = 0;
    for (var k = 0; k < 32; k++) value = ((value << 1) | nbit()) >>> 0;
    var out = [];
    for (var s = 0; s < cnt; s++) {
      var base = prevCtx * 8, val = 0;
      for (var bp = 0; bp < 8; bp++) {
        var idx = base + bp, p = probs[idx];
        var rng = high - low + 1;
        var mid = (low + Math.floor(rng * p / 2048)) >>> 0;
        var bit;
        if (value < mid) { high = (mid - 1) >>> 0; probs[idx] = (p + ((2048 - p) >> 5)) >>> 0; bit = 0; }
        else { low = mid; probs[idx] = (p - (p >> 5)) >>> 0; bit = 1; }
        val = (val << 1) | bit;
        for (;;) {
          if (high < Z4_HALF) { /* pass */ }
          else if (low >= Z4_HALF) { value = (value - Z4_HALF) >>> 0; low = (low - Z4_HALF) >>> 0; high = (high - Z4_HALF) >>> 0; }
          else if (low >= Z4_QTR1 && high < Z4_QTR3) { value = (value - Z4_QTR1) >>> 0; low = (low - Z4_QTR1) >>> 0; high = (high - Z4_QTR1) >>> 0; }
          else break;
          low = (low << 1) >>> 0; high = ((high << 1) | 1) >>> 0;
          value = ((value << 1) | nbit()) >>> 0;
        }
      }
      var byte = val & 255;
      out.push(byte);
      if (byte === 0) prevCtx = 3;
      else if (byte === 1 || byte === 3) prevCtx = 1;
      else if (byte === 2) prevCtx = 2;
      else prevCtx = 0;
    }
    return new Uint8Array(out);
  }
  function z4Compress(data) {
    var tokens = z3LzCompress(data);
    var enc = z4Encode(tokens);
    var out = new Uint8Array(4 + enc.length);
    out.set(u32be(tokens.length), 0);
    out.set(enc, 4);
    return out;
  }
  function z4Decompress(data) { return z3LzDecompress(z4Decode(data)); }

  /* ---------- z5 专用 LZ（最小匹配 3，LZMA 级短匹配） ---------- */
  function z5LzCompress(data) {
    var n = data.length, out = [], i = 0, chain = new Map();
    function h3(p) { return (data[p] << 16) | (data[p + 1] << 8) | data[p + 2]; }
    function findMatch(pos) {
      if (pos + 3 > n) return [0, 0];
      var last = chain.has(h3(pos)) ? chain.get(h3(pos)) : -1;
      if (last < 0 || pos - last > Z3_WINDOW) return [0, 0];
      var m = 0;
      while (m < 258 && pos + m < n && data[last + m] === data[pos + m]) m++;
      if (m < 3) return [0, 0];
      return [m, pos - last];
    }
    while (i < n) {
      var r = findMatch(i), bl = r[0], bo = r[1];
      if (bl >= 3) {
        if (i + 4 <= n) {
          var r2 = findMatch(i + 1);
          if (r2[0] > bl + 1) {
            var b = data[i];
            if (b === 0x00 || b === 0x01 || b === 0x02 || b === 0x03) out.push(0x00, b);
            else out.push(b);
            if (i + 3 <= n) chain.set(h3(i), i);
            i++; continue;
          }
        }
        if (bo <= 0xFFFF) {
          out.push(0x01, (bo >> 8) & 255, bo & 255, Math.min(bl, 258) - 3);
        } else {
          out.push(0x03, (bo >> 16) & 255, (bo >> 8) & 255, bo & 255, Math.min(bl, 258) - 3);
        }
        for (var k = 0; k < bl; k++) if (i + k + 3 <= n) chain.set(h3(i + k), i + k);
        i += bl;
      } else {
        var j = i + 1;
        while (j < n && data[j] === data[i] && j - i < 258) j++;
        if (j - i >= 3) {
          out.push(0x02, (j - i) - 3, data[i]);
          for (var k2 = 0; k2 < j - i; k2++) if (i + k2 + 3 <= n) chain.set(h3(i + k2), i + k2);
          i = j;
        } else {
          var b2 = data[i];
          if (b2 === 0x00 || b2 === 0x01 || b2 === 0x02 || b2 === 0x03) out.push(0x00, b2);
          else out.push(b2);
          if (i + 3 <= n) chain.set(h3(i), i);
          i++;
        }
      }
    }
    return new Uint8Array(out);
  }
  function z5LzDecompress(tokens) {
    var out = [], i = 0, n = tokens.length;
    while (i < n) {
      var t = tokens[i];
      if (t === 0x00) { out.push(tokens[i + 1]); i += 2; }
      else if (t === 0x01) {
        var off = (tokens[i + 1] << 8) | tokens[i + 2];
        var ln = tokens[i + 3] + 3;
        var src = out.length - off;
        for (var k = 0; k < ln; k++) { out.push(out[src]); src++; }
        i += 4;
      } else if (t === 0x03) {
        var off2 = (tokens[i + 1] << 16) | (tokens[i + 2] << 8) | tokens[i + 3];
        var ln2 = tokens[i + 4] + 3;
        var src2 = out.length - off2;
        for (var m2 = 0; m2 < ln2; m2++) { out.push(out[src2]); src2++; }
        i += 5;
      } else if (t === 0x02) {
        var rl = tokens[i + 1] + 3;
        for (var m3 = 0; m3 < rl; m3++) out.push(tokens[i + 2]);
        i += 3;
      } else { out.push(t); i++; }
    }
    return new Uint8Array(out);
  }

  /* ---------- XHCZ5（2.3 极限压缩：结构感知 order-2 高阶上下文预测） ---------- */
  function z5Encode(data) {
    var probs = new Uint16Array(65536 * 8).fill(1024);
    var low = 0, high = Z4_MASK, pending = 0, bits = [], p2 = 0, p1 = 0;
    var cats = new Uint8Array(data.length);
    // 类别：自由位 4（含控制符），参数区 off=1 len=2 runlen=3
    (function buildCats() {
      var i = 0, n = data.length;
      while (i < n) {
        var b = data[i];
        cats[i] = 4;
        if (b === 0x00) { if (i + 1 < n) cats[i + 1] = 4; i += 2; }
        else if (b === 0x01) { if (i + 3 < n) { cats[i+1]=1; cats[i+2]=1; cats[i+3]=2; } i += 4; }
        else if (b === 0x02) { if (i + 2 < n) { cats[i+1]=3; cats[i+2]=4; } i += 3; }
        else if (b === 0x03) { if (i + 4 < n) { cats[i+1]=1; cats[i+2]=1; cats[i+3]=1; cats[i+4]=2; } i += 5; }
        else i++;
      }
    })();
    function bpf(b) { bits.push(b); while (pending > 0) { bits.push(b ^ 1); pending--; } }
    for (var i = 0; i < data.length; i++) {
      var byte = data[i], cat = cats[i];
      var base = (((cat << 13) | ((p1 << 8) | p2) & 0x1FFF)) * 8;
      for (var bp = 0; bp < 8; bp++) {
        var bit = (byte >> (7 - bp)) & 1, idx = base + bp, pr = probs[idx];
        var rng = high - low + 1;
        var mid = (low + Math.floor(rng * pr / 2048)) >>> 0;
        if (bit === 0) { high = (mid - 1) >>> 0; probs[idx] = (pr + ((2048 - pr) >> 5)) >>> 0; }
        else { low = mid; probs[idx] = (pr - (pr >> 5)) >>> 0; }
        for (;;) {
          if (high < Z4_HALF) { bpf(0); low = (low << 1) >>> 0; high = ((high << 1) | 1) >>> 0; }
          else if (low >= Z4_HALF) { bpf(1); low = (low - Z4_HALF) >>> 0; high = (high - Z4_HALF) >>> 0; low = (low << 1) >>> 0; high = ((high << 1) | 1) >>> 0; }
          else if (low >= Z4_QTR1 && high < Z4_QTR3) { pending++; low = (low - Z4_QTR1) >>> 0; high = (high - Z4_QTR1) >>> 0; low = (low << 1) >>> 0; high = ((high << 1) | 1) >>> 0; }
          else break;
        }
      }
      p2 = p1; p1 = byte;
    }
    pending += 1;
    if (low < Z4_QTR1) bpf(0); else bpf(1);
    while (bits.length % 8) bits.push(0);
    var out = [];
    for (var k = 0; k < bits.length; k += 8) {
      var bb = 0;
      for (var j = 0; j < 8; j++) bb = (bb << 1) | bits[k + j];
      out.push(bb);
    }
    return new Uint8Array(out);
  }
  function z5Decode(data) {
    var probs = new Uint16Array(65536 * 8).fill(1024);
    var cnt = readU32(data, 0);
    var pos = 4, cur = 0, n = 0, limit = data.length, p2 = 0, p1 = 0;
    function nbit() {
      if (n === 0) { if (pos >= limit) return 0; cur = data[pos]; pos++; n = 8; }
      var b = (cur >> 7) & 1; cur = (cur << 1) & 255; n--; return b;
    }
    var low = 0, high = Z4_MASK, value = 0;
    for (var k = 0; k < 32; k++) value = ((value << 1) | nbit()) >>> 0;
    var out = [];
    var params = [];
    for (var s = 0; s < cnt; s++) {
      var cat = params.length > 0 ? params[0] : 4;
      var base = (((cat << 13) | ((p1 << 8) | p2) & 0x1FFF)) * 8;
      var val = 0;
      for (var bp = 0; bp < 8; bp++) {
        var idx = base + bp, pr = probs[idx];
        var rng = high - low + 1;
        var mid = (low + Math.floor(rng * pr / 2048)) >>> 0;
        var bit;
        if (value < mid) { high = (mid - 1) >>> 0; probs[idx] = (pr + ((2048 - pr) >> 5)) >>> 0; bit = 0; }
        else { low = mid; probs[idx] = (pr - (pr >> 5)) >>> 0; bit = 1; }
        val = (val << 1) | bit;
        for (;;) {
          if (high < Z4_HALF) { /* pass */ }
          else if (low >= Z4_HALF) { value = (value - Z4_HALF) >>> 0; low = (low - Z4_HALF) >>> 0; high = (high - Z4_HALF) >>> 0; }
          else if (low >= Z4_QTR1 && high < Z4_QTR3) { value = (value - Z4_QTR1) >>> 0; low = (low - Z4_QTR1) >>> 0; high = (high - Z4_QTR1) >>> 0; }
          else break;
          low = (low << 1) >>> 0; high = ((high << 1) | 1) >>> 0;
          value = ((value << 1) | nbit()) >>> 0;
        }
      }
      var byte = val & 255;
      out.push(byte);
      if (params.length > 0) params.shift();
      else {
        if (byte === 0x00) params = [4];
        else if (byte === 0x01) params = [1, 1, 2];
        else if (byte === 0x02) params = [3, 4];
        else if (byte === 0x03) params = [1, 1, 1, 2];
      }
      p2 = p1; p1 = byte;
    }
    return new Uint8Array(out);
  }
  function z5Compress(data) {
    var tokens = z5LzCompress(data);
    var enc = z5Encode(tokens);
    var out = new Uint8Array(4 + enc.length);
    out.set(u32be(tokens.length), 0);
    out.set(enc, 4);
    return out;
  }
  function z5Decompress(data) { return z5LzDecompress(z5Decode(data)); }



  /* ---------- XHCZ6（2.5 极限压缩第二代：PAQ 式双模型混合） ---------- */
  var Z6_CTX2 = 65536 * 8, Z6_CTX3 = (1 << 20) * 8, Z6_MUL = 2654435761;
  var STRETCH_TAB = (function () {
    var t = new Int32Array(2049);
    t[0] = -1024; t[2048] = 1024;
    for (var i = 1; i < 2048; i++) {
      var v = 64 * Math.log(i / (2048 - i));
      var s = v >= 0 ? Math.floor(v + 0.5) : -Math.floor(-v + 0.5);
      t[i] = Math.max(-1024, Math.min(1024, s));
    }
    return t;
  })();
  var SQUASH_TAB = (function () {
    var t = new Int32Array(2049);
    for (var s = -1024; s <= 1024; s++) {
      var p = 2048 / (1 + Math.exp(-s / 64));
      t[s + 1024] = Math.max(0, Math.min(2048, Math.floor(p + 0.5)));
    }
    return t;
  })();
  function z6Wupd(err, s, shift) {
    var prod = err * s;
    var d = Math.abs(prod) >> shift;
    return prod >= 0 ? d : -d;
  }
  function z6Ctx3(cat, p1, p2, p3) {
    var h = Math.imul((p1 << 16) ^ (p2 << 8) ^ p3, Z6_MUL) >>> 0;
    return ((cat << 17) | ((h >> 15) & 0x1FFFF)) * 8;
  }
  function z6Cats(data) {
    var n = data.length, cats = new Uint8Array(n), i = 0;
    while (i < n) {
      var b = data[i];
      cats[i] = 4;
      if (b === 0x00) { if (i + 1 < n) cats[i + 1] = 4; i += 2; }
      else if (b === 0x01) { if (i + 3 < n) { cats[i+1]=1; cats[i+2]=1; cats[i+3]=2; } i += 4; }
      else if (b === 0x02) { if (i + 2 < n) { cats[i+1]=3; cats[i+2]=4; } i += 3; }
      else if (b === 0x03) { if (i + 4 < n) { cats[i+1]=1; cats[i+2]=1; cats[i+3]=1; cats[i+4]=2; } i += 5; }
      else i++;
    }
    return cats;
  }
  function z6Encode(data) {
    var m2 = new Uint16Array(Z6_CTX2).fill(1024);
    var m3 = new Uint16Array(Z6_CTX3).fill(1024);
    var w2 = 2048, w3 = 2048;
    var low = 0, high = Z4_MASK, pending = 0, bits = [];
    var p3 = 0, p2 = 0, p1 = 0;
    var cats = z6Cats(data);
    for (var i = 0; i < data.length; i++) {
      var cat = cats[i];
      var base2 = (((cat << 13) | ((p1 << 8) | p2) & 0x1FFF)) * 8;
      var base3 = z6Ctx3(cat, p1, p2, p3);
      for (var bp = 0; bp < 8; bp++) {
        var bit = (data[i] >> (7 - bp)) & 1;
        var idx2 = base2 + bp, idx3 = base3 + bp;
        var pr2 = m2[idx2], pr3 = m3[idx3];
        var s2 = STRETCH_TAB[2048 - pr2], s3 = STRETCH_TAB[2048 - pr3];
        var smix = Math.floor((w2 * s2 + w3 * s3) / 4096);
        smix = Math.max(-1024, Math.min(1024, smix));
        var p = Math.max(1, Math.min(2047, SQUASH_TAB[smix + 1024]));
        var rng = high - low + 1;
        var mid = (low + Math.floor((rng * p) / 2048)) >>> 0;
        if (bit === 1) {
          high = (mid - 1) >>> 0;
          m2[idx2] = pr2 - (pr2 >> 5);
          m3[idx3] = pr3 - (pr3 >> 5);
        } else {
          low = mid;
          m2[idx2] = pr2 + ((2048 - pr2) >> 5);
          m3[idx3] = pr3 + ((2048 - pr3) >> 5);
        }
        var err = (bit << 11) - p;
        w2 += z6Wupd(err, s2, 12);
        w3 += z6Wupd(err, s3, 12);
        w2 = Math.max(256, Math.min(32768, w2));
        w3 = Math.max(256, Math.min(32768, w3));
        for (;;) {
          if (high < Z4_HALF) {
            bits.push(0);
            while (pending > 0) { bits.push(1); pending--; }
          } else if (low >= Z4_HALF) {
            bits.push(1);
            while (pending > 0) { bits.push(0); pending--; }
            low = (low - Z4_HALF) >>> 0; high = (high - Z4_HALF) >>> 0;
          } else if (low >= Z4_QTR1 && high < Z4_QTR3) {
            pending++;
            low = (low - Z4_QTR1) >>> 0; high = (high - Z4_QTR1) >>> 0;
          } else break;
          low = (low << 1) >>> 0; high = ((high << 1) | 1) >>> 0;
        }
      }
      p3 = p2; p2 = p1; p1 = data[i];
    }
    pending += 1;
    if (low < Z4_QTR1) { bits.push(0); while (pending > 0) { bits.push(1); pending--; } }
    else { bits.push(1); while (pending > 0) { bits.push(0); pending--; } }
    while (bits.length % 8) bits.push(0);
    var out = [];
    for (var k = 0; k < bits.length; k += 8) {
      var bb = 0;
      for (var j = 0; j < 8; j++) bb = (bb << 1) | bits[k + j];
      out.push(bb);
    }
    return new Uint8Array(out);
  }
  function z6Decode(data) {
    var m2 = new Uint16Array(Z6_CTX2).fill(1024);
    var m3 = new Uint16Array(Z6_CTX3).fill(1024);
    var w2 = 2048, w3 = 2048;
    var cnt = readU32(data, 0);
    var pos = 4, cur = 0, n = 0, limit = data.length, p3 = 0, p2 = 0, p1 = 0;
    function nbit() {
      if (n === 0) { if (pos >= limit) return 0; cur = data[pos]; pos++; n = 8; }
      var b = (cur >> 7) & 1; cur = (cur << 1) & 255; n--;
      return b;
    }
    var low = 0, high = Z4_MASK, value = 0;
    for (var k = 0; k < 32; k++) value = ((value << 1) | nbit()) >>> 0;
    var out = [];
    var params = [];
    for (var s = 0; s < cnt; s++) {
      var cat = params.length > 0 ? params[0] : 4;
      var base2 = (((cat << 13) | ((p1 << 8) | p2) & 0x1FFF)) * 8;
      var base3 = z6Ctx3(cat, p1, p2, p3);
      var byte = 0;
      for (var bp = 0; bp < 8; bp++) {
        var idx2 = base2 + bp, idx3 = base3 + bp;
        var pr2 = m2[idx2], pr3 = m3[idx3];
        var s2 = STRETCH_TAB[2048 - pr2], s3 = STRETCH_TAB[2048 - pr3];
        var smix = Math.floor((w2 * s2 + w3 * s3) / 4096);
        smix = Math.max(-1024, Math.min(1024, smix));
        var p = Math.max(1, Math.min(2047, SQUASH_TAB[smix + 1024]));
        var rng = high - low + 1;
        var mid = (low + Math.floor((rng * p) / 2048)) >>> 0;
        var bit;
        if (value < mid) {
          bit = 1; high = (mid - 1) >>> 0;
          m2[idx2] = pr2 - (pr2 >> 5);
          m3[idx3] = pr3 - (pr3 >> 5);
        } else {
          bit = 0; low = mid;
          m2[idx2] = pr2 + ((2048 - pr2) >> 5);
          m3[idx3] = pr3 + ((2048 - pr3) >> 5);
        }
        byte = (byte << 1) | bit;
        var err = (bit << 11) - p;
        w2 += z6Wupd(err, s2, 12);
        w3 += z6Wupd(err, s3, 12);
        w2 = Math.max(256, Math.min(32768, w2));
        w3 = Math.max(256, Math.min(32768, w3));
        for (;;) {
          if (high < Z4_HALF) { /* pass */ }
          else if (low >= Z4_HALF) { value = (value - Z4_HALF) >>> 0; low = (low - Z4_HALF) >>> 0; high = (high - Z4_HALF) >>> 0; }
          else if (low >= Z4_QTR1 && high < Z4_QTR3) { value = (value - Z4_QTR1) >>> 0; low = (low - Z4_QTR1) >>> 0; high = (high - Z4_QTR1) >>> 0; }
          else break;
          low = (low << 1) >>> 0; high = ((high << 1) | 1) >>> 0;
          value = ((value << 1) | nbit()) >>> 0;
        }
      }
      out.push(byte);
      if (params.length > 0) params.shift();
      else {
        if (byte === 0x00) params = [4];
        else if (byte === 0x01) params = [1, 1, 2];
        else if (byte === 0x02) params = [3, 4];
        else if (byte === 0x03) params = [1, 1, 1, 2];
      }
      p3 = p2; p2 = p1; p1 = byte;
    }
    return new Uint8Array(out);
  }
  function z6Compress(data) {
    var tokens = z5LzCompress(data);
    var enc = z6Encode(tokens);
    var out = new Uint8Array(4 + enc.length);
    out.set(u32be(tokens.length), 0);
    out.set(enc, 4);
    return out;
  }
  function z6Decompress(data) { return z5LzDecompress(z6Decode(data)); }


  /* ---------- XHCZ7（2.9 多模型上下文混合 CM：order-1/2/3/4 四路混合，构造性优于 Optima） ---------- */
  var Z7_MUL = 2654435761;
  var Z7_CTX1 = 256 * 8;       // order-1 表（prev byte × 8）
  var Z7_CTX2 = 65536 * 8;     // order-2 + 角色 表
  var Z7_CTX3 = (1 << 19) * 8; // order-3 哈希 表
  var Z7_CTX4 = (1 << 19) * 8; // order-4 哈希 表
  var ADAPT_MODE_SS = 0, ADAPT_MODE_PRO = 1, ADAPT_MODE_STORE = 2, ADAPT_MODE_Z4 = 3, ADAPT_MODE_Z6 = 4, ADAPT_MODE_Z3 = 5, ADAPT_MODE_Z7 = 6;

  function z7Ctx3(cat, p1, p2, p3) {
    var h = Math.imul((p1 << 16) ^ (p2 << 8) ^ p3, Z7_MUL) >>> 0;
    return ((cat << 16) | ((h >> 15) & 0xFFFF)) * 8;
  }
  function z7Ctx4(cat, p1, p2, p3, p4) {
    var h = Math.imul((p1 << 24) ^ (p2 << 16) ^ (p3 << 8) ^ p4, Z7_MUL) >>> 0;
    return ((cat << 16) | ((h >> 15) & 0xFFFF)) * 8;
  }
  function z7Encode(data) {
    var m1 = new Uint16Array(Z7_CTX1).fill(1024);
    var m2 = new Uint16Array(Z7_CTX2).fill(1024);
    var m3 = new Uint16Array(Z7_CTX3).fill(1024);
    var m4 = new Uint16Array(Z7_CTX4).fill(1024);
    var w1 = 2048, w2 = 2048, w3 = 2048, w4 = 2048;
    var low = 0, high = Z4_MASK, pending = 0, bits = [];
    var p4 = 0, p3 = 0, p2 = 0, p1 = 0;
    var cats = z6Cats(data);
    for (var i = 0; i < data.length; i++) {
      var cat = cats[i];
      var base1 = p1 * 8;
      var base2 = (((cat << 13) | ((p1 << 8) | p2) & 0x1FFF)) * 8;
      var base3 = z7Ctx3(cat, p1, p2, p3);
      var base4 = z7Ctx4(cat, p1, p2, p3, p4);
      for (var bp = 0; bp < 8; bp++) {
        var bit = (data[i] >> (7 - bp)) & 1;
        var idx1 = base1 + bp, idx2 = base2 + bp, idx3 = base3 + bp, idx4 = base4 + bp;
        var pr1 = m1[idx1], pr2 = m2[idx2], pr3 = m3[idx3], pr4 = m4[idx4];
        var s1 = STRETCH_TAB[2048 - pr1], s2 = STRETCH_TAB[2048 - pr2], s3 = STRETCH_TAB[2048 - pr3], s4 = STRETCH_TAB[2048 - pr4];
        var smix = Math.floor((w1 * s1 + w2 * s2 + w3 * s3 + w4 * s4) / 4096);
        smix = Math.max(-1024, Math.min(1024, smix));
        var p = Math.max(1, Math.min(2047, SQUASH_TAB[smix + 1024]));
        var rng = high - low + 1;
        var mid = low + Math.floor((rng * p) / 2048);
        if (bit === 1) {
          high = mid - 1;  // 保持未掩码，精确镜像 Python 无界整数语义（renorm 末尾才 >>>0 掩码）
          m1[idx1] = pr1 - (pr1 >> 5);
          m2[idx2] = pr2 - (pr2 >> 5);
          m3[idx3] = pr3 - (pr3 >> 5);
          m4[idx4] = pr4 - (pr4 >> 5);
        } else {
          low = mid;
          m1[idx1] = pr1 + ((2048 - pr1) >> 5);
          m2[idx2] = pr2 + ((2048 - pr2) >> 5);
          m3[idx3] = pr3 + ((2048 - pr3) >> 5);
          m4[idx4] = pr4 + ((2048 - pr4) >> 5);
        }
        var err = (bit << 11) - p;
        w1 += z6Wupd(err, s1, 12);
        w2 += z6Wupd(err, s2, 12);
        w3 += z6Wupd(err, s3, 12);
        w4 += z6Wupd(err, s4, 12);
        w1 = Math.max(256, Math.min(32768, w1));
        w2 = Math.max(256, Math.min(32768, w2));
        w3 = Math.max(256, Math.min(32768, w3));
        w4 = Math.max(256, Math.min(32768, w4));
        for (;;) {
          if (high < Z4_HALF) {
            bits.push(0);
            while (pending > 0) { bits.push(1); pending--; }
          } else if (low >= Z4_HALF) {
            bits.push(1);
            while (pending > 0) { bits.push(0); pending--; }
            low = low - Z4_HALF; high = high - Z4_HALF;
          } else if (low >= Z4_QTR1 && high < Z4_QTR3) {
            pending++;
            low = low - Z4_QTR1; high = high - Z4_QTR1;
          } else break;
          low = (low << 1) >>> 0; high = ((high << 1) | 1) >>> 0;
        }
      }
      p4 = p3; p3 = p2; p2 = p1; p1 = data[i];
    }
    pending += 1;
    if (low < Z4_QTR1) { bits.push(0); while (pending > 0) { bits.push(1); pending--; } }
    else { bits.push(1); while (pending > 0) { bits.push(0); pending--; } }
    while (bits.length % 8) bits.push(0);
    var out = [];
    for (var k = 0; k < bits.length; k += 8) {
      var bb = 0;
      for (var j = 0; j < 8; j++) bb = (bb << 1) | bits[k + j];
      out.push(bb);
    }
    return new Uint8Array(out);
  }
  function z7Decode(data) {
    var m1 = new Uint16Array(Z7_CTX1).fill(1024);
    var m2 = new Uint16Array(Z7_CTX2).fill(1024);
    var m3 = new Uint16Array(Z7_CTX3).fill(1024);
    var m4 = new Uint16Array(Z7_CTX4).fill(1024);
    var w1 = 2048, w2 = 2048, w3 = 2048, w4 = 2048;
    var cnt = readU32(data, 0);
    var pos = 4, cur = 0, n = 0, limit = data.length, p4 = 0, p3 = 0, p2 = 0, p1 = 0;
    function nbit() {
      if (n === 0) { if (pos >= limit) return 0; cur = data[pos]; pos++; n = 8; }
      var b = (cur >> 7) & 1; cur = (cur << 1) & 255; n--;
      return b;
    }
    var low = 0, high = Z4_MASK, value = 0;
    for (var k = 0; k < 32; k++) value = ((value << 1) | nbit()) >>> 0;
    var out = [];
    var params = [];
    for (var s = 0; s < cnt; s++) {
      var cat = params.length > 0 ? params[0] : 4;
      var base1 = p1 * 8;
      var base2 = (((cat << 13) | ((p1 << 8) | p2) & 0x1FFF)) * 8;
      var base3 = z7Ctx3(cat, p1, p2, p3);
      var base4 = z7Ctx4(cat, p1, p2, p3, p4);
      var byte = 0;
      for (var bp = 0; bp < 8; bp++) {
        var idx1 = base1 + bp, idx2 = base2 + bp, idx3 = base3 + bp, idx4 = base4 + bp;
        var pr1 = m1[idx1], pr2 = m2[idx2], pr3 = m3[idx3], pr4 = m4[idx4];
        var s1 = STRETCH_TAB[2048 - pr1], s2 = STRETCH_TAB[2048 - pr2], s3 = STRETCH_TAB[2048 - pr3], s4 = STRETCH_TAB[2048 - pr4];
        var smix = Math.floor((w1 * s1 + w2 * s2 + w3 * s3 + w4 * s4) / 4096);
        smix = Math.max(-1024, Math.min(1024, smix));
        var p = Math.max(1, Math.min(2047, SQUASH_TAB[smix + 1024]));
        var rng = high - low + 1;
        var mid = low + Math.floor((rng * p) / 2048);
        var bit;
        if (value < mid) {
          bit = 1; high = mid - 1;  // 保持未掩码，精确镜像 Python 无界整数语义（renorm 末尾才 >>>0 掩码）
          m1[idx1] = pr1 - (pr1 >> 5);
          m2[idx2] = pr2 - (pr2 >> 5);
          m3[idx3] = pr3 - (pr3 >> 5);
          m4[idx4] = pr4 - (pr4 >> 5);
        } else {
          bit = 0; low = mid;
          m1[idx1] = pr1 + ((2048 - pr1) >> 5);
          m2[idx2] = pr2 + ((2048 - pr2) >> 5);
          m3[idx3] = pr3 + ((2048 - pr3) >> 5);
          m4[idx4] = pr4 + ((2048 - pr4) >> 5);
        }
        byte = (byte << 1) | bit;
        var err = (bit << 11) - p;
        w1 += z6Wupd(err, s1, 12);
        w2 += z6Wupd(err, s2, 12);
        w3 += z6Wupd(err, s3, 12);
        w4 += z6Wupd(err, s4, 12);
        w1 = Math.max(256, Math.min(32768, w1));
        w2 = Math.max(256, Math.min(32768, w2));
        w3 = Math.max(256, Math.min(32768, w3));
        w4 = Math.max(256, Math.min(32768, w4));
        for (;;) {
          if (high < Z4_HALF) { /* pass */ }
          else if (low >= Z4_HALF) { value = (value - Z4_HALF) >>> 0; low = low - Z4_HALF; high = high - Z4_HALF; }
          else if (low >= Z4_QTR1 && high < Z4_QTR3) { value = (value - Z4_QTR1) >>> 0; low = low - Z4_QTR1; high = high - Z4_QTR1; }
          else break;
          low = (low << 1) >>> 0; high = ((high << 1) | 1) >>> 0;
          value = ((value << 1) | nbit()) >>> 0;
        }
      }
      out.push(byte);
      if (params.length > 0) params.shift();
      else {
        if (byte === 0x00) params = [4];
        else if (byte === 0x01) params = [1, 1, 2];
        else if (byte === 0x02) params = [3, 4];
        else if (byte === 0x03) params = [1, 1, 1, 2];
      }
      p4 = p3; p3 = p2; p2 = p1; p1 = byte;
    }
    return new Uint8Array(out);
  }
  function z7Compress(data) {
    var tokens = z3LzCompress(data);
    var enc = z7Encode(tokens);
    var out = new Uint8Array(4 + enc.length);
    out.set(u32be(tokens.length), 0);
    out.set(enc, 4);
    return out;
  }
  function z7Decompress(data) { return z3LzDecompress(z7Decode(data)); }

  // XHCZ8（XEBZ 2.10）：x8 单流 = z8 4MB-LZ + 复用 z7 四模型混合 CM；x8auto = 全局 min(x8, adapt, store)
  function x8Compress(data) {
    var tokens = z8LzCompress(data);
    var enc = z7Encode(tokens);
    var out = new Uint8Array(4 + enc.length);
    out.set(u32be(tokens.length), 0);
    out.set(enc, 4);
    return out;
  }
  function x8Decompress(data) { return z3LzDecompress(z7Decode(data)); }
  function x8autoCompress(data) {
    if (data.length === 0) return concatBytes(new Uint8Array([2]), u32be(0));
    var c8 = x8Compress(data);
    var ca = adaptCompress(data);
    var cands = [[c8.length, 0, c8], [ca.length, 1, ca], [data.length, 2, data]];
    cands.sort(function (a, b) { return a[0] - b[0]; });
    var best = cands[0];
    var mode = best[1], payload = best[2];
    if (mode === 2) return concatBytes(new Uint8Array([2]), u32be(payload.length), payload);
    return concatBytes(new Uint8Array([mode]), payload);
  }
  function x8autoDecompress(data) {
    var mode = data[0];
    if (mode === 2) {
      var plen = readU32(data, 1);
      var payload = data.subarray(5, 5 + plen);
      return payload;
    }
    var payload = data.subarray(1);
    if (mode === 0) return x8Decompress(payload);
    return adaptDecompress(payload);
  }

  function adaptCompress(data) {
    var n = data.length;
    if (n === 0) return u32be(0);
    var chunks = [];
    var nb = Math.ceil(n / OPTIMA_BLOCK);
    chunks.push(u32be(nb));
    for (var bi = 0; bi < nb; bi++) {
      var start = bi * OPTIMA_BLOCK, end = Math.min(n, start + OPTIMA_BLOCK);
      var blk = data.subarray(start, end);
      var L = blk.length;
      var ss = ssCompress(blk);
      var z3 = z3Compress(blk);
      var z4 = z4Compress(blk);
      var z6 = z6Compress(blk);
      var pro = prossCompress(blk);
      var z7c = z7Compress(blk);
      var cands = [
        [ss.length, ADAPT_MODE_SS, ss],
        [z3.length, ADAPT_MODE_Z3, z3],
        [z4.length, ADAPT_MODE_Z4, z4],
        [z6.length, ADAPT_MODE_Z6, z6],
        [pro.length, ADAPT_MODE_PRO, pro],
        [z7c.length, ADAPT_MODE_Z7, z7c],
        [L, ADAPT_MODE_STORE, blk]
      ];
      cands.sort(function (a, b) { return a[0] - b[0]; });
      var best = cands[0];
      var head = [];
      head.push(best[1]);
      head.push.apply(head, u32be(best[2].length));
      chunks.push(new Uint8Array(head));
      chunks.push(best[2]);
    }
    return concatBytes.apply(null, chunks);
  }
  function adaptDecompress(data) {
    var nb = readU32(data, 0);
    var pos = 4, chunks = [];
    for (var i = 0; i < nb; i++) {
      var mode = data[pos++];
      var plen = readU32(data, pos); pos += 4;
      var payload = data.subarray(pos, pos + plen); pos += plen;
      var dec;
      if (mode === ADAPT_MODE_SS) dec = ssDecompress(payload);
      else if (mode === ADAPT_MODE_Z3) dec = z3Decompress(payload);
      else if (mode === ADAPT_MODE_Z4) dec = z4Decompress(payload);
      else if (mode === ADAPT_MODE_Z6) dec = z6Decompress(payload);
      else if (mode === ADAPT_MODE_PRO) dec = prossDecompress(payload);
      else if (mode === ADAPT_MODE_Z7) dec = z7Decompress(payload);
      else dec = payload;
      chunks.push(dec);
    }
    return concatBytes.apply(null, chunks);
  }




  /* ---------- XHCZ-ProSS（2.7 综合产品线：增强 LZ + 智能四档分派） ---------- */
  var PROSS_MODE_PRO = 0, PROSS_MODE_DUAL = 1, PROSS_MODE_FAST = 2, PROSS_MODE_STORE = 3;
  var _PRO_CTX1 = 256 * 8;  // order-1 表：256 上下文 × 8 位平面（与 Z6_CTX2/Z6_CTX3/Z6_MUL 复用）

  function prossEntropySample(data, limit) {
    limit = limit || 8192;
    var seg = data.subarray(0, Math.min(limit, data.length));
    var n = seg.length;
    if (n < 16) return 0.0;
    var freq = new Float64Array(256);
    for (var i = 0; i < n; i++) freq[seg[i]]++;
    var h = 0.0;
    for (var c = 0; c < 256; c++) {
      if (freq[c] > 0) { var p = freq[c] / n; h -= p * Math.log(p) / Math.LN2; }
    }
    return h;
  }
  function prossPickMode(tokens) {
    var n = tokens.length;
    if (n < 64) return PROSS_MODE_DUAL;
    var h = prossEntropySample(tokens);
    if (h > 7.6) return PROSS_MODE_STORE;
    if (n > 256 * 1024) return PROSS_MODE_FAST;
    if (h < 6.8) return PROSS_MODE_PRO;
    return PROSS_MODE_DUAL;
  }

  /* mode 0：三模型混合（order-1 字节 + order-2 角色分流 + order-3 哈希） */
  function prossEncodePro(data) {
    var m1 = new Uint16Array(_PRO_CTX1).fill(1024);
    var m2 = new Uint16Array(Z6_CTX2).fill(1024);
    var m3 = new Uint16Array(Z6_CTX3).fill(1024);
    var w1 = 2048, w2 = 2048, w3 = 2048;
    var low = 0, high = Z4_MASK, pending = 0, bits = [];
    var p3 = 0, p2 = 0, p1 = 0;
    var cats = z6Cats(data);
    for (var i = 0; i < data.length; i++) {
      var cat = cats[i];
      var base1 = (p1 << 3);
      var base2 = (((cat << 13) | ((p1 << 8) | p2) & 0x1FFF)) * 8;
      var base3 = z6Ctx3(cat, p1, p2, p3);
      for (var bp = 0; bp < 8; bp++) {
        var bit = (data[i] >> (7 - bp)) & 1;
        var i1 = base1 + bp, i2 = base2 + bp, i3 = base3 + bp;
        var pr1 = m1[i1], pr2 = m2[i2], pr3 = m3[i3];
        var s1 = STRETCH_TAB[2048 - pr1], s2 = STRETCH_TAB[2048 - pr2], s3 = STRETCH_TAB[2048 - pr3];
        var smix = Math.floor((w1 * s1 + w2 * s2 + w3 * s3) / 4096);
        smix = Math.max(-1024, Math.min(1024, smix));
        var p = Math.max(1, Math.min(2047, SQUASH_TAB[smix + 1024]));
        var rng = high - low + 1;
        var mid = (low + Math.floor((rng * p) / 2048)) >>> 0;
        if (bit === 1) {
          high = (mid - 1) >>> 0;
          m1[i1] = pr1 - (pr1 >> 5);
          m2[i2] = pr2 - (pr2 >> 5);
          m3[i3] = pr3 - (pr3 >> 5);
        } else {
          low = mid;
          m1[i1] = pr1 + ((2048 - pr1) >> 5);
          m2[i2] = pr2 + ((2048 - pr2) >> 5);
          m3[i3] = pr3 + ((2048 - pr3) >> 5);
        }
        var err = (bit << 11) - p;
        w1 += z6Wupd(err, s1, 12);
        w2 += z6Wupd(err, s2, 12);
        w3 += z6Wupd(err, s3, 12);
        w1 = Math.max(256, Math.min(32768, w1));
        w2 = Math.max(256, Math.min(32768, w2));
        w3 = Math.max(256, Math.min(32768, w3));
        for (;;) {
          if (high < Z4_HALF) {
            bits.push(0);
            while (pending > 0) { bits.push(1); pending--; }
          } else if (low >= Z4_HALF) {
            bits.push(1);
            while (pending > 0) { bits.push(0); pending--; }
            low = (low - Z4_HALF) >>> 0; high = (high - Z4_HALF) >>> 0;
          } else if (low >= Z4_QTR1 && high < Z4_QTR3) {
            pending++;
            low = (low - Z4_QTR1) >>> 0; high = (high - Z4_QTR1) >>> 0;
          } else break;
          low = (low << 1) >>> 0; high = ((high << 1) | 1) >>> 0;
        }
      }
      p3 = p2; p2 = p1; p1 = data[i];
    }
    pending += 1;
    if (low < Z4_QTR1) { bits.push(0); while (pending > 0) { bits.push(1); pending--; } }
    else { bits.push(1); while (pending > 0) { bits.push(0); pending--; } }
    while (bits.length % 8) bits.push(0);
    var out = [];
    for (var k = 0; k < bits.length; k += 8) {
      var bb = 0;
      for (var j = 0; j < 8; j++) bb = (bb << 1) | bits[k + j];
      out.push(bb);
    }
    return new Uint8Array(out);
  }

  function prossDecodePro(data, symCount) {
    var m1 = new Uint16Array(_PRO_CTX1).fill(1024);
    var m2 = new Uint16Array(Z6_CTX2).fill(1024);
    var m3 = new Uint16Array(Z6_CTX3).fill(1024);
    var w1 = 2048, w2 = 2048, w3 = 2048;
    var pos = 0, cur = 0, n = 0, limit = data.length;
    function nbit() {
      if (n === 0) { if (pos >= limit) return 0; cur = data[pos]; pos++; n = 8; }
      var b = (cur >> 7) & 1; cur = (cur << 1) & 255; n--; return b;
    }
    var low = 0, high = Z4_MASK, value = 0;
    for (var k = 0; k < 32; k++) value = ((value << 1) | nbit()) >>> 0;
    var out = [];
    var params = [];
    var p3 = 0, p2 = 0, p1 = 0;
    for (var s = 0; s < symCount; s++) {
      var cat = params.length > 0 ? params[0] : 4;
      var base1 = (p1 << 3);
      var base2 = (((cat << 13) | ((p1 << 8) | p2) & 0x1FFF)) * 8;
      var base3 = z6Ctx3(cat, p1, p2, p3);
      var byte = 0;
      for (var bp = 0; bp < 8; bp++) {
        var i1 = base1 + bp, i2 = base2 + bp, i3 = base3 + bp;
        var pr1 = m1[i1], pr2 = m2[i2], pr3 = m3[i3];
        var s1 = STRETCH_TAB[2048 - pr1], s2 = STRETCH_TAB[2048 - pr2], s3 = STRETCH_TAB[2048 - pr3];
        var smix = Math.floor((w1 * s1 + w2 * s2 + w3 * s3) / 4096);
        smix = Math.max(-1024, Math.min(1024, smix));
        var p = Math.max(1, Math.min(2047, SQUASH_TAB[smix + 1024]));
        var rng = high - low + 1;
        var mid = (low + Math.floor((rng * p) / 2048)) >>> 0;
        var bit;
        if (value < mid) {
          bit = 1; high = (mid - 1) >>> 0;
          m1[i1] = pr1 - (pr1 >> 5);
          m2[i2] = pr2 - (pr2 >> 5);
          m3[i3] = pr3 - (pr3 >> 5);
        } else {
          bit = 0; low = mid;
          m1[i1] = pr1 + ((2048 - pr1) >> 5);
          m2[i2] = pr2 + ((2048 - pr2) >> 5);
          m3[i3] = pr3 + ((2048 - pr3) >> 5);
        }
        byte = (byte << 1) | bit;
        var err = (bit << 11) - p;
        w1 += z6Wupd(err, s1, 12);
        w2 += z6Wupd(err, s2, 12);
        w3 += z6Wupd(err, s3, 12);
        w1 = Math.max(256, Math.min(32768, w1));
        w2 = Math.max(256, Math.min(32768, w2));
        w3 = Math.max(256, Math.min(32768, w3));
        for (;;) {
          if (high < Z4_HALF) { /* pass */ }
          else if (low >= Z4_HALF) {
            value = (value - Z4_HALF) >>> 0; low = (low - Z4_HALF) >>> 0; high = (high - Z4_HALF) >>> 0;
          } else if (low >= Z4_QTR1 && high < Z4_QTR3) {
            value = (value - Z4_QTR1) >>> 0; low = (low - Z4_QTR1) >>> 0; high = (high - Z4_QTR1) >>> 0;
          } else break;
          low = (low << 1) >>> 0; high = ((high << 1) | 1) >>> 0;
          value = ((value << 1) | nbit()) >>> 0;
        }
      }
      out.push(byte);
      if (params.length > 0) params.shift();
      else {
        if (byte === 0x00) params = [4];
        else if (byte === 0x01) params = [1, 1, 2];
        else if (byte === 0x02) params = [3, 4];
        else if (byte === 0x03) params = [1, 1, 1, 2];
      }
      p3 = p2; p2 = p1; p1 = byte;
    }
    return new Uint8Array(out);
  }

  // mode 1 均衡双模型 = z6 双模型（order-2 角色分流 + order-3 哈希）
  var prossEncodeDual = z6Encode;
  function prossDecodeDual(data, symCount) {
    var m2 = new Uint16Array(Z6_CTX2).fill(1024);
    var m3 = new Uint16Array(Z6_CTX3).fill(1024);
    var w2 = 2048, w3 = 2048;
    var pos = 0, cur = 0, n = 0, limit = data.length;
    function nbit() {
      if (n === 0) { if (pos >= limit) return 0; cur = data[pos]; pos++; n = 8; }
      var b = (cur >> 7) & 1; cur = (cur << 1) & 255; n--; return b;
    }
    var low = 0, high = Z4_MASK, value = 0;
    for (var k = 0; k < 32; k++) value = ((value << 1) | nbit()) >>> 0;
    var out = [];
    var params = [];
    var p3 = 0, p2 = 0, p1 = 0;
    for (var s = 0; s < symCount; s++) {
      var cat = params.length > 0 ? params[0] : 4;
      var base2 = (((cat << 13) | ((p1 << 8) | p2) & 0x1FFF)) * 8;
      var base3 = z6Ctx3(cat, p1, p2, p3);
      var byte = 0;
      for (var bp = 0; bp < 8; bp++) {
        var i2 = base2 + bp, i3 = base3 + bp;
        var pr2 = m2[i2], pr3 = m3[i3];
        var s2 = STRETCH_TAB[2048 - pr2], s3 = STRETCH_TAB[2048 - pr3];
        var smix = Math.floor((w2 * s2 + w3 * s3) / 4096);
        smix = Math.max(-1024, Math.min(1024, smix));
        var p = Math.max(1, Math.min(2047, SQUASH_TAB[smix + 1024]));
        var rng = high - low + 1;
        var mid = (low + Math.floor((rng * p) / 2048)) >>> 0;
        var bit;
        if (value < mid) {
          bit = 1; high = (mid - 1) >>> 0;
          m2[i2] = pr2 - (pr2 >> 5);
          m3[i3] = pr3 - (pr3 >> 5);
        } else {
          bit = 0; low = mid;
          m2[i2] = pr2 + ((2048 - pr2) >> 5);
          m3[i3] = pr3 + ((2048 - pr3) >> 5);
        }
        byte = (byte << 1) | bit;
        var err = (bit << 11) - p;
        w2 += z6Wupd(err, s2, 12);
        w3 += z6Wupd(err, s3, 12);
        w2 = Math.max(256, Math.min(32768, w2));
        w3 = Math.max(256, Math.min(32768, w3));
        for (;;) {
          if (high < Z4_HALF) { /* pass */ }
          else if (low >= Z4_HALF) {
            value = (value - Z4_HALF) >>> 0; low = (low - Z4_HALF) >>> 0; high = (high - Z4_HALF) >>> 0;
          } else if (low >= Z4_QTR1 && high < Z4_QTR3) {
            value = (value - Z4_QTR1) >>> 0; low = (low - Z4_QTR1) >>> 0; high = (high - Z4_QTR1) >>> 0;
          } else break;
          low = (low << 1) >>> 0; high = ((high << 1) | 1) >>> 0;
          value = ((value << 1) | nbit()) >>> 0;
        }
      }
      out.push(byte);
      if (params.length > 0) params.shift();
      else {
        if (byte === 0x00) params = [4];
        else if (byte === 0x01) params = [1, 1, 2];
        else if (byte === 0x02) params = [3, 4];
        else if (byte === 0x03) params = [1, 1, 1, 2];
      }
      p3 = p2; p2 = p1; p1 = byte;
    }
    return new Uint8Array(out);
  }

  function prossCompress(data) {
    var tokens = z5LzCompress(data);
    var mode = prossPickMode(tokens);
    var head = concatBytes(u32be(tokens.length), new Uint8Array([mode]));
    if (mode === PROSS_MODE_PRO) return concatBytes(head, prossEncodePro(tokens));
    if (mode === PROSS_MODE_DUAL) return concatBytes(head, prossEncodeDual(tokens));
    if (mode === PROSS_MODE_FAST) return concatBytes(head, u32be(tokens.length), z5Encode(tokens));
    return concatBytes(head, tokens);  // STORE（原样 token 流）
  }
  function prossDecompress(data) {
    var symCount = readU32(data, 0);
    var mode = data[4];
    var body = data.subarray(5);
    var tokens;
    if (mode === PROSS_MODE_PRO) tokens = prossDecodePro(body, symCount);
    else if (mode === PROSS_MODE_DUAL) tokens = prossDecodeDual(body, symCount);
    else if (mode === PROSS_MODE_FAST) tokens = z5Decode(body);
    else tokens = body;
    return z5LzDecompress(tokens);
  }


  /* ---------- XHCZ-Optima（2.8 六边形战士：逐块择优 ss / pro / z3 / z4 / z6 / store） ---------- */
  function optimaCompress(data) {
    var n = data.length;
    if (n === 0) return u32be(0);
    var chunks = [];
    var nb = Math.ceil(n / OPTIMA_BLOCK);
    chunks.push(u32be(nb));
    for (var bi = 0; bi < nb; bi++) {
      var start = bi * OPTIMA_BLOCK, end = Math.min(n, start + OPTIMA_BLOCK);
      var blk = data.subarray(start, end);
      var L = blk.length;
      var ss = ssCompress(blk);
      var z3 = z3Compress(blk);
      var z4 = z4Compress(blk);
      var z6 = z6Compress(blk);
      var pro = prossCompress(blk);
      var cands = [
        [ss.length, OPTIMA_MODE_SS, ss],
        [z3.length, OPTIMA_MODE_Z3, z3],
        [z4.length, OPTIMA_MODE_Z4, z4],
        [z6.length, OPTIMA_MODE_Z6, z6],
        [pro.length, OPTIMA_MODE_PRO, pro],
        [L, OPTIMA_MODE_STORE, blk]
      ];
      cands.sort(function (a, b) { return a[0] - b[0]; });
      var best = cands[0];
      var head = [];
      head.push(best[1]);
      head.push.apply(head, u32be(best[2].length));   // 5 字节，安全
      chunks.push(new Uint8Array(head));
      chunks.push(best[2]);                            // 直接压入 Uint8Array，避免 push.apply 大数组爆栈
    }
    return concatBytes.apply(null, chunks);
  }
  function optimaDecompress(data) {
    var nb = readU32(data, 0);
    var pos = 4, chunks = [];
    for (var i = 0; i < nb; i++) {
      var mode = data[pos++];
      var plen = readU32(data, pos); pos += 4;
      var payload = data.subarray(pos, pos + plen); pos += plen;
      var dec;
      if (mode === OPTIMA_MODE_SS) dec = ssDecompress(payload);
      else if (mode === OPTIMA_MODE_Z3) dec = z3Decompress(payload);
      else if (mode === OPTIMA_MODE_Z4) dec = z4Decompress(payload);
      else if (mode === OPTIMA_MODE_Z6) dec = z6Decompress(payload);
      else if (mode === OPTIMA_MODE_PRO) dec = prossDecompress(payload);
      else dec = payload;
      chunks.push(dec);
    }
    return concatBytes.apply(null, chunks);
  }


  /* ---------- XHC-SS SpeedSafe I（2.6 速度+安全：64KB 快速 LZ + 哈夫曼） ---------- */
  var SS_WINDOW = 65536;
  function ssLzCompress(data) {
    /* 单遍快速 LZ：64KB 窗口哈希链 + 贪心最长匹配 + run（与 Python ss_lz_compress 一致） */
    var n = data.length, out = [], i = 0, chain = new Map();
    while (i < n) {
      var bestLen = 0, bestOff = 0;
      if (i + 3 <= n) {
        var h = (data[i] << 16) | (data[i + 1] << 8) | data[i + 2];
        var last = chain.has(h) ? chain.get(h) : -1;
        if (last >= 0 && i - last <= SS_WINDOW) {
          var m = 0;
          while (m < 258 && i + m < n && data[last + m] === data[i + m]) m++;
          if (m >= 4) { bestLen = m; bestOff = i - last; }
        }
      }
      if (bestLen >= 4) {
        out.push(TOKEN_MATCH, (bestOff >> 8) & 255, bestOff & 255, Math.min(bestLen, 258) - 4);
        for (var k = 0; k < bestLen; k++)
          if (i + k + 3 <= n) chain.set((data[i+k]<<16)|(data[i+k+1]<<8)|data[i+k+2], i + k);
        i += bestLen;
      } else {
        var j = i + 1;
        while (j < n && data[j] === data[i] && j - i < 258) j++;
        if (j - i >= 4) {
          out.push(TOKEN_RUN, (j - i) - 4, data[i]);
          for (var k2 = 0; k2 < j - i; k2++)
            if (i + k2 + 3 <= n) chain.set((data[i+k2]<<16)|(data[i+k2+1]<<8)|data[i+k2+2], i + k2);
          i = j;
        } else {
          var b = data[i];
          if (b === TOKEN_ESC || b === TOKEN_MATCH || b === TOKEN_RUN) out.push(TOKEN_ESC, b);
          else out.push(b);
          if (i + 3 <= n) chain.set((data[i]<<16)|(data[i+1]<<8)|data[i+2], i);
          i++;
        }
      }
    }
    return new Uint8Array(out);
  }
  function ssCompress(data) { return huffmanEncode(ssLzCompress(data)); }
  function ssDecompress(data) { return z2LzDecompress(huffmanDecode(data)); }

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


  /* ---------- Combo3 双层加密：AES-256-GCM（WebCrypto） ---------- */
  async function aesGcmEncrypt(keyBytes, iv, data) {
    var key = await crypto.subtle.importKey('raw', keyBytes, { name: 'AES-GCM' }, false, ['encrypt']);
    return new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv, tagLength: 128 }, key, data));
  }
  async function aesGcmDecrypt(keyBytes, iv, data) {
    var key = await crypto.subtle.importKey('raw', keyBytes, { name: 'AES-GCM' }, false, ['decrypt']);
    return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv, tagLength: 128 }, key, data));
  }
  /* ---------- pack / unpack ---------- */
  function pickBlock(data, method) {
    /* 返回 [use, block]。method='auto' 全部择优（XHCZ8=x8auto=min(z8单流,adapt分块,store) 为首项，保证不劣于 XHCZ7(adapt) 与 Optima）；否则强制指定算法（更大则 store 兜底） */
    var z6, z5, z4, z3, z2, c1, pro;
    if (!method || method === 'auto') {
      var ad = adaptCompress(data);
      var z8b = x8Compress(data);   // XHCZ8 单流 = z8 4MB-LZ + 复用 z7 四模型 CM
      pro = prossCompress(data);
      z6 = z6Compress(data); z5 = z5Compress(data); z4 = z4Compress(data); z3 = z3Compress(data);
      z2 = z2Compress(data); c1 = comboCompress(data);
      // XHCZ8 产品（默认 auto）：全局 min over {z8, adapt, pro, z6.., store}，返回原生方法字节（无嵌套标签，顶层容器对 z8/adapt 一视同仁）
      if (z8b.length <= ad.length && z8b.length <= pro.length && z8b.length <= z6.length && z8b.length <= z5.length && z8b.length <= z4.length && z8b.length <= z3.length && z8b.length <= z2.length && z8b.length <= c1.length && z8b.length <= data.length) return [METHOD_Z8, z8b];
      if (ad.length <= pro.length && ad.length <= z6.length && ad.length <= z5.length && ad.length <= z4.length && ad.length <= z3.length && ad.length <= z2.length && ad.length <= c1.length && ad.length <= data.length) return [METHOD_ADAPT, ad];
      if (pro.length <= z6.length && pro.length <= z5.length && pro.length <= z4.length && pro.length <= z3.length && pro.length <= z2.length && pro.length <= c1.length && pro.length <= data.length) return [METHOD_PRO, pro];
      if (z6.length <= z5.length && z6.length <= z4.length && z6.length <= z3.length && z6.length <= z2.length && z6.length <= c1.length && z6.length <= data.length) return [METHOD_Z6, z6];
      if (z5.length <= z4.length && z5.length <= z3.length && z5.length <= z2.length && z5.length <= c1.length && z5.length <= data.length) return [METHOD_Z5, z5];
      if (z4.length <= z3.length && z4.length <= z2.length && z4.length <= c1.length && z4.length <= data.length) return [METHOD_Z4, z4];
      if (z3.length <= z2.length && z3.length <= c1.length && z3.length <= data.length) return [METHOD_Z3, z3];
      if (z2.length <= c1.length && z2.length <= data.length) return [METHOD_Z2, z2];
      if (c1.length < data.length) return [METHOD_COMBO, c1];
      return [METHOD_STORE, data];
    }
    if (method === 'store') return [METHOD_STORE, data];
    if (method === 'combo') { c1 = comboCompress(data); return c1.length < data.length ? [METHOD_COMBO, c1] : [METHOD_STORE, data]; }
    if (method === 'z2') { z2 = z2Compress(data); return z2.length < data.length ? [METHOD_Z2, z2] : [METHOD_STORE, data]; }
    if (method === 'z3') { z3 = z3Compress(data); return z3.length < data.length ? [METHOD_Z3, z3] : [METHOD_STORE, data]; }
    if (method === 'z4') { z4 = z4Compress(data); return z4.length < data.length ? [METHOD_Z4, z4] : [METHOD_STORE, data]; }
    if (method === 'z5') { z5 = z5Compress(data); return z5.length < data.length ? [METHOD_Z5, z5] : [METHOD_STORE, data]; }
    if (method === 'z6') { z6 = z6Compress(data); return z6.length < data.length ? [METHOD_Z6, z6] : [METHOD_STORE, data]; }
    if (method === 'ss') { var ss = ssCompress(data); return ss.length < data.length ? [METHOD_SS, ss] : [METHOD_STORE, data]; }
    if (method === 'pro') { var prob = prossCompress(data); return prob.length < data.length ? [METHOD_PRO, prob] : [METHOD_STORE, data]; }
    if (method === 'optima') { var optb = optimaCompress(data); return optb.length < data.length ? [METHOD_OPTIMA, optb] : [METHOD_STORE, data]; }
    if (method === 'z7') { var z7b = z7Compress(data); return z7b.length < data.length ? [METHOD_Z7, z7b] : [METHOD_STORE, data]; }
    if (method === 'adapt') { var adb = adaptCompress(data); return adb.length < data.length ? [METHOD_ADAPT, adb] : [METHOD_STORE, data]; }
    if (method === 'z8') { var z8bb = x8Compress(data); return z8bb.length < data.length ? [METHOD_Z8, z8bb] : [METHOD_STORE, data]; }
    if (method === 'x8auto') {
      // XHCZ8 聚焦产品：全局 min over {z8 单流, adapt 分块, store}，返回原生方法字节（无嵌套标签）
      var z8xb = x8Compress(data);
      var adxb = adaptCompress(data);
      if (z8xb.length <= adxb.length && z8xb.length <= data.length) return [METHOD_Z8, z8xb];
      if (adxb.length <= data.length) return [METHOD_ADAPT, adxb];
      return [METHOD_STORE, data];
    }
    return [METHOD_STORE, data];
  }

  async function pack(files, password, method, packKdf) {
    /* files: [{name, data: Uint8Array}] → Uint8Array(.xebz)
       method: 'auto'(默认)/'store'/'combo'/'z2'/'z3'/'z4'/'z5' */
    assertCrypto();
    var pl = [], i;
    pl.push(u32be(files.length));
    var blocks = [];
    for (i = 0; i < files.length; i++) {
      var f = files[i];
      var nb = te.encode(f.name);
      var crc = crc32(f.data);
      var picked = pickBlock(f.data, method);
      var use = picked[0], block = picked[1];
      pl.push(u32be(nb.length));
      pl.push(nb);
      pl.push(u64be(f.data.length));
      pl.push(new Uint8Array([use]));
      pl.push(u32be(crc));
      blocks.push(block);
    }
    for (i = 0; i < blocks.length; i++) {
      pl.push(u64be(blocks[i].length));
      pl.push(blocks[i]);   // 直接压入 Uint8Array 块，避免 push.apply 大数组爆栈
    }
    var payloadPlain = concatBytes.apply(null, pl);

    var kdf = KDF_NONE, salt = new Uint8Array(16), iv = new Uint8Array(12), iters = 0, payload = payloadPlain;
    if (password) {
      if (packKdf === KDF_COMBO3) {
        // XHC-Combo3 强化安全内核：Argon2id 64MB/t4/p2 派生 512-bit → 双层 AEAD
        var ac3 = global.XHCCRYPTO;
        if (!ac3) throw new Error('安全内核未加载（缺少 xhc_crypto.js）');
        kdf = KDF_COMBO3;
        var salt3 = crypto.getRandomValues(new Uint8Array(16));
        var iv1 = crypto.getRandomValues(new Uint8Array(12));
        var iv2 = crypto.getRandomValues(new Uint8Array(12));
        var key64 = await ac3.argon2id(String(password), salt3, 64 * 1024, 4, 2, 64);
        var k1 = key64.slice(0, 32), k2 = key64.slice(32, 64);
        var r1 = ac3.chacha20Poly1305Encrypt(k1, iv1, payloadPlain, null);
        var inner = concatBytes(r1.ct, r1.tag);
        var outer = await aesGcmEncrypt(k2, iv2, inner);
        var head = [];
        head.push.apply(head, MAGIC);
        head.push.apply(head, u16be(VERSION));
        head.push(KDF_COMBO3);
        head.push.apply(head, u32be(4));
        head.push.apply(head, u32be(64 * 1024));
        head.push(2);
        head.push(CIPHER_DUAL);
        head.push(salt3.length);
        head.push.apply(head, salt3);
        head.push(iv1.length);
        head.push.apply(head, iv1);
        head.push.apply(head, iv2);
        head.push.apply(head, u64be(outer.length));
        return concatBytes(new Uint8Array(head), outer);
      }
      // XHC-Combo2 安全内核：Argon2id + ChaCha20-Poly1305（默认）
      // XHC-Combo2 安全内核：Argon2id + ChaCha20-Poly1305（默认）
      var ac2 = global.XHCCRYPTO;
      if (!ac2) throw new Error('安全内核未加载（缺少 xhc_crypto.js）');
      kdf = KDF_ARGON2;
      salt = crypto.getRandomValues(new Uint8Array(16));
      iv = crypto.getRandomValues(new Uint8Array(12));
      var key = await ac2.argon2id(String(password), salt, 32 * 1024, 3, 1, 32);
      var res = ac2.chacha20Poly1305Encrypt(key, iv, payloadPlain, null);
      payload = concatBytes(res.ct, res.tag);
      var head = [];
      head.push.apply(head, MAGIC);
      head.push.apply(head, u16be(VERSION));
      head.push(KDF_ARGON2);
      head.push.apply(head, u32be(3));           // time_cost
      head.push.apply(head, u32be(32 * 1024));   // memory_cost KB
      head.push(1);                              // parallelism
      head.push(CIPHER_CHACHA20);                // cipher
      head.push(salt.length);
      head.push.apply(head, salt);
      head.push(iv.length);
      head.push.apply(head, iv);
      head.push.apply(head, u64be(payload.length));
      return concatBytes(new Uint8Array(head), payload);
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
    if ((ver >> 8) !== 1 && (ver >> 8) !== 2) throw new Error('不支持的版本: 0x' + ver.toString(16));
    var kdf = u8[8];
    var plain;
    if (kdf === KDF_COMBO3) {
      // Combo3：Argon2id 64MB 派生 512-bit → AES 外层解 → ChaCha 内层解
      var ac3 = global.XHCCRYPTO;
      if (!ac3) throw new Error('安全内核未加载（缺少 xhc_crypto.js）');
      if (!password) throw new Error('该文件已加密，需要密码');
      var t3 = readU32(u8, 9), mem3 = readU32(u8, 13), par3 = u8[17], ciph3 = u8[18];
      var saltLen3 = u8[19];
      var salt3 = u8.subarray(20, 20 + saltLen3);
      var iv1 = u8.subarray(37, 49);
      var iv2 = u8.subarray(49, 61);
      var plen3 = readU64(u8, 61);
      var payload3 = u8.subarray(69, 69 + plen3);
      var key643 = await ac3.argon2id(String(password), salt3, mem3, t3, par3, 64);
      var k1 = key643.slice(0, 32), k2 = key643.slice(32, 64);
      try {
        var inner3 = await aesGcmDecrypt(k2, iv2, payload3);
        var ct1 = inner3.subarray(0, inner3.length - 16);
        var tag1 = inner3.subarray(inner3.length - 16);
        plain = ac3.chacha20Poly1305Decrypt(k1, iv1, ct1, tag1, null);
      } catch (e) { throw new Error('解密失败：密码错误或文件已损坏（Combo3 双重认证）'); }
    } else if (kdf === KDF_ARGON2) {
      // XHC-Combo2：Argon2id + ChaCha20-Poly1305
      var ac2 = global.XHCCRYPTO;
      if (!ac2) throw new Error('安全内核未加载（缺少 xhc_crypto.js）');
      if (!password) throw new Error('该文件已加密，需要密码');
      var t2 = readU32(u8, 9), mem2 = readU32(u8, 13), par2 = u8[17], ciph2 = u8[18];
      var saltLen2 = u8[19];
      var salt2 = u8.subarray(20, 20 + saltLen2);
      var iv2 = u8.subarray(37, 49);
      var plen2 = readU64(u8, 49);
      var payload2 = u8.subarray(57, 57 + plen2);
      var key2 = await ac2.argon2id(String(password), salt2, mem2, t2, par2, 32);
      var ct2 = payload2.subarray(0, payload2.length - 16);
      var tag2 = payload2.subarray(payload2.length - 16);
      try {
        plain = ac2.chacha20Poly1305Decrypt(key2, iv2, ct2, tag2, null);
      } catch (e) { throw new Error('解密失败：密码错误或文件已损坏'); }
    } else if (kdf === KDF_PBKDF2) {
      var iters = readU32(u8, 9);
      var saltLen = u8[13], ivLen = u8[30];
      var salt = u8.subarray(14, 14 + saltLen);
      var iv = u8.subarray(31, 31 + ivLen);
      var plen = readU64(u8, 43);
      var payload = u8.subarray(51, 51 + plen);
      if (!password) throw new Error('该文件已加密，需要密码');
      var key = await deriveKey(String(password), salt, iters);
      try {
        plain = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv, tagLength: 128 }, key, payload));
      } catch (e) { throw new Error('解密失败：密码错误或文件已损坏'); }
    } else if (kdf === KDF_NONE) {
      if (password) throw new Error('该文件未加密，无需密码');
      var plen0 = readU64(u8, 43);
      plain = u8.subarray(51, 51 + plen0);
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
      else if (headers[i].method === METHOD_Z6) data = z6Decompress(blocks[i]);
      else if (headers[i].method === METHOD_SS) data = ssDecompress(blocks[i]);
      else if (headers[i].method === METHOD_PRO) data = prossDecompress(blocks[i]);
      else if (headers[i].method === METHOD_OPTIMA) data = optimaDecompress(blocks[i]);
      else if (headers[i].method === METHOD_ADAPT) data = adaptDecompress(blocks[i]);
      else if (headers[i].method === METHOD_Z7) data = z7Decompress(blocks[i]);
      else if (headers[i].method === METHOD_Z8) data = x8Decompress(blocks[i]);
      else if (headers[i].method === METHOD_X8AUTO) data = x8autoDecompress(blocks[i]);
      else if (headers[i].method === METHOD_Z5) data = z5Decompress(blocks[i]);
      else if (headers[i].method === METHOD_Z4) data = z4Decompress(blocks[i]);
      else if (headers[i].method === METHOD_Z3) data = z3Decompress(blocks[i]);
      else if (headers[i].method === METHOD_Z2) data = z2Decompress(blocks[i]);
      else if (headers[i].method === METHOD_STORE) data = blocks[i];
      else throw new Error('不支持的压缩方法: ' + headers[i].method);
      if (crc32(data) !== headers[i].crc32) throw new Error('校验失败（数据损坏?）: ' + headers[i].name);
      out.push({ name: headers[i].name, data: data });
    }
    return out;
  }

  global.XEBZ = {
    VERSION: '2.10',
    FORMAT: 'XHCBZ-v1',
    METHODS: { auto: '自动（XHCZ8 单流+自适应择优）', store: '仅存储', combo: 'XHC-Combo',
               z2: 'XHCZ2', z3: 'XHCZ3', z4: 'XHCZ4', z5: 'XHCZ5', z6: 'XHCZ6', ss: 'XHC-SS SpeedSafe', pro: 'XHCZ-ProSS', optima: 'XHCZ-Optima 六边形战士', z7: 'XHCZ7 多模型上下文混合', adapt: 'XHCZ7 自适应择优', z8: 'XHCZ8 单流（4MB-LZ+z7 CM）', x8auto: 'XHCZ8 自动择优（推荐）' },
    METHOD_IDS: ['auto', 'store', 'combo', 'z2', 'z3', 'z4', 'z5', 'z6', 'ss', 'pro', 'optima', 'z7', 'adapt', 'z8', 'x8auto'],
    pack: pack,
    unpack: unpack,
    comboCompress: comboCompress,
    comboDecompress: comboDecompress,
    z2Compress: z2Compress,
    z2Decompress: z2Decompress,
    z2LzCompress: z2LzCompress,
    z2LzDecompress: z2LzDecompress,
    z2AceEncode: z2AceEncode,
    z3Compress: z3Compress,
    z3Decompress: z3Decompress,
    z3LzCompress: z3LzCompress,
    z3LzDecompress: z3LzDecompress,
    z4Compress: z4Compress,
    z4Decompress: z4Decompress,
    z5Compress: z5Compress,
    z5Decompress: z5Decompress,
    z6Compress: z6Compress,
    z6Decompress: z6Decompress,
    ssCompress: ssCompress,
    ssDecompress: ssDecompress,
    prossCompress: prossCompress,
    prossDecompress: prossDecompress,
    prossPickMode: prossPickMode,
    optimaCompress: optimaCompress,
    optimaDecompress: optimaDecompress,
    z7Compress: z7Compress,
    z7Decompress: z7Decompress,
    z7Encode: z7Encode,
    z7Decode: z7Decode,
    adaptCompress: adaptCompress,
    adaptDecompress: adaptDecompress,
    x8Compress: x8Compress,
    x8Decompress: x8Decompress,
    x8autoCompress: x8autoCompress,
    x8autoDecompress: x8autoDecompress,
    z8LzCompress: z8LzCompress,
    z5LzCompress: z5LzCompress,
    z5LzDecompress: z5LzDecompress,
    z5LzCompress: z5LzCompress,
    z5LzDecompress: z5LzDecompress
  };
})(typeof window !== 'undefined' ? window : (typeof globalThis !== 'undefined' ? globalThis : this));
