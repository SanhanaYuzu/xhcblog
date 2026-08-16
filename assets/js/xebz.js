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
  var VERSION = 0x0202;  // 2.2（读取兼容 1.x / 2.0 / 2.1）
  var KDF_NONE = 0, KDF_PBKDF2 = 1;
  var DEFAULT_ITER = 100000;
  var HEADER_LEN = 51;
  var METHOD_STORE = 0, METHOD_COMBO = 1, METHOD_Z2 = 2, METHOD_Z3 = 3, METHOD_Z4 = 4;
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
  var Z3_WINDOW = 1 << 20, Z3_BLOCK = 65536;
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
      } else { out.push(t); i++; }
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
      var z4 = z4Compress(f.data);
      var z3 = z3Compress(f.data);
      var z2 = z2Compress(f.data);
      var c1 = comboCompress(f.data);
      var use, block;
      if (z4.length <= z3.length && z4.length <= z2.length && z4.length <= c1.length && z4.length <= f.data.length) { use = METHOD_Z4; block = z4; }
      else if (z3.length <= z2.length && z3.length <= c1.length && z3.length <= f.data.length) { use = METHOD_Z3; block = z3; }
      else if (z2.length <= c1.length && z2.length <= f.data.length) { use = METHOD_Z2; block = z2; }
      else if (c1.length < f.data.length) { use = METHOD_COMBO; block = c1; }
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
    if ((ver >> 8) !== 1 && (ver >> 8) !== 2) throw new Error('不支持的版本: 0x' + ver.toString(16));
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
    VERSION: '1.0.0',
    FORMAT: 'XHCBZ-v1',
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
    z4Compress: z4Compress,
    z4Decompress: z4Decompress
  };
})(typeof window !== 'undefined' ? window : (typeof globalThis !== 'undefined' ? globalThis : this));
