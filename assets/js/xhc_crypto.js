/* ============================================================
 * XHC-Crypto — XHC-Combo2 安全内核的浏览器实现
 *  ChaCha20-Poly1305（RFC 8439，自研实现，纯 JS）
 *  Argon2id（RFC 9106，经测试的 hash-wasm 实现，与 Python cryptography 互通）
 * 注意：先加载 hash-wasm（assets/vendor/hash-wasm.js），再加载本文件
 * ============================================================ */
(function (global) {
  'use strict';

  var U8 = Uint8Array, U32 = Uint32Array, Big = BigInt, B0 = 0n;

  function rotl32(x, n) {
    x >>>= 0;
    return ((x << n) | (x >>> (32 - n))) >>> 0;
  }
  function QR(s, a, b, c, d) {
    s[a] = (s[a] + s[b]) >>> 0; s[d] = rotl32(s[d] ^ s[a], 16);
    s[c] = (s[c] + s[d]) >>> 0; s[b] = rotl32(s[b] ^ s[c], 12);
    s[a] = (s[a] + s[b]) >>> 0; s[d] = rotl32(s[d] ^ s[a], 8);
    s[c] = (s[c] + s[d]) >>> 0; s[b] = rotl32(s[b] ^ s[c], 7);
  }
  function chachaBlock(key, counter, nonce) {
    var state = new Uint32Array(16);
    var consts = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];
    for (var i = 0; i < 4; i++) state[i] = consts[i];
    for (var j = 0; j < 8; j++) {
      state[4 + j] = (key[j * 4] | (key[j * 4 + 1] << 8) | (key[j * 4 + 2] << 16) | (key[j * 4 + 3] << 24)) >>> 0;
    }
    state[12] = counter >>> 0;
    state[13] = (nonce[0] | (nonce[1] << 8) | (nonce[2] << 16) | (nonce[3] << 24)) >>> 0;
    state[14] = (nonce[4] | (nonce[5] << 8) | (nonce[6] << 16) | (nonce[7] << 24)) >>> 0;
    state[15] = (nonce[8] | (nonce[9] << 8) | (nonce[10] << 16) | (nonce[11] << 24)) >>> 0;
    var w = state.slice();
    for (var round = 0; round < 10; round++) {
      QR(w, 0, 4, 8, 12); QR(w, 1, 5, 9, 13); QR(w, 2, 6, 10, 14); QR(w, 3, 7, 11, 15);
      QR(w, 0, 5, 10, 15); QR(w, 1, 6, 11, 12); QR(w, 2, 7, 8, 13); QR(w, 3, 4, 9, 14);
    }
    var out = new Uint32Array(16);
    for (var k = 0; k < 16; k++) out[k] = (w[k] + state[k]) >>> 0;
    return out;
  }
  function chacha20Xor(key, counter, nonce, data) {
    var out = new U8(data.length);
    var block = new U8(64);
    for (var pos = 0; pos < data.length; pos += 64) {
      var words = chachaBlock(key, counter + pos / 64, nonce);
      for (var i = 0; i < 16; i++) {
        block[i * 4] = words[i] & 255;
        block[i * 4 + 1] = (words[i] >>> 8) & 255;
        block[i * 4 + 2] = (words[i] >>> 16) & 255;
        block[i * 4 + 3] = (words[i] >>> 24) & 255;
      }
      for (var k = 0; k < 64 && pos + k < data.length; k++) out[pos + k] = data[pos + k] ^ block[k];
    }
    return out;
  }
  function poly1305(msg, key) {
    var p1305 = (Big(1) << Big(130)) - Big(5);
    var r = B0;
    for (var i = 0; i < 16; i++) r |= Big(key[i]) << Big(8 * i);
    r &= Big('0x0ffffffc0ffffffc0ffffffc0fffffff');
    var s = B0;
    for (var j = 16; j < 32; j++) s |= Big(key[j]) << Big(8 * (j - 16));
    var acc = B0, pos = 0;
    while (pos < msg.length) {
      var n = Math.min(16, msg.length - pos);
      var chunk = B0;
      for (var k = 0; k < n; k++) chunk |= Big(msg[pos + k]) << Big(8 * k);
      // RFC 8439 §2.5.1：每个块都追加 0x01 位（满块加 2^128，短块加 2^(8n)）
      chunk |= Big(1) << Big(8 * n);
      acc = (acc + chunk) % p1305;
      acc = (acc * r) % p1305;
      pos += 16;
    }
    var full = acc + s;
    var out = new U8(16);
    for (var i2 = 0; i2 < 16; i2++) out[i2] = Number((full >> Big(8 * i2)) & 0xFFn);
    return out;
  }
  function pad16(n) { var l = (16 - (n % 16)) % 16; return new U8(l); }
  function u64le(n) {
    var o = new U8(8);
    for (var i = 0; i < 8; i++) o[i] = Math.floor(n / Math.pow(2, 8 * i)) % 256;
    return o;
  }
  function strToBytes(s) {
    var o = new U8(s.length);
    for (var i = 0; i < s.length; i++) o[i] = s.charCodeAt(i) & 255;
    return o;
  }
  function macInput(aad, ct) {
    var aadPad = pad16(aad.length), ctPad = pad16(ct.length);
    var macIn = new U8(aad.length + aadPad.length + ct.length + ctPad.length + 16);
    var p = 0;
    macIn.set(aad, p); p += aad.length;
    macIn.set(aadPad, p); p += aadPad.length;
    macIn.set(ct, p); p += ct.length;
    macIn.set(ctPad, p); p += ctPad.length;
    macIn.set(u64le(aad.length), p); p += 8;
    macIn.set(u64le(ct.length), p);
    return macIn;
  }
  function chacha20Poly1305Encrypt(key, nonce, plaintext, aad) {
    aad = aad || new U8(0);
    var subkey = chacha20Xor(key, 0, nonce, new U8(32));
    var ct = chacha20Xor(key, 1, nonce, plaintext);
    var tag = poly1305(macInput(aad, ct), subkey);
    return { ct: ct, tag: tag };
  }
  function chacha20Poly1305Decrypt(key, nonce, ct, tag, aad) {
    aad = aad || new U8(0);
    var subkey = chacha20Xor(key, 0, nonce, new U8(32));
    var calc = poly1305(macInput(aad, ct), subkey);
    var diff = 0;
    for (var i = 0; i < 16; i++) diff |= calc[i] ^ tag[i];
    if (diff !== 0) throw new Error('解密失败：密码错误或文件已损坏');
    return chacha20Xor(key, 1, nonce, ct);
  }

  /* ================= Argon2id（hash-wasm） ================= */
  function argon2id(pwd, salt, memKB, t, par, outLen) {
    outLen = outLen || 32;
    if (!global.hashwasm || !global.hashwasm.argon2id) {
      return Promise.reject(new Error('hash-wasm 未加载（缺少 assets/vendor/hash-wasm.js）'));
    }
    // 每次调用独立派生（不可缓存：salt/参数每次不同）
    return global.hashwasm.argon2id({
      password: typeof pwd === 'string' ? pwd : bytesToStr(pwd),
      salt: salt,
      memorySize: memKB,           // KB
      iterations: t,
      parallelism: par,
      hashLength: outLen,
      outputType: 'binary'
    });
  }
  function bytesToStr(b) {
    var s = '';
    for (var i = 0; i < b.length; i++) s += String.fromCharCode(b[i]);
    return s;
  }

  var AC2 = {
    chacha20Poly1305Encrypt: chacha20Poly1305Encrypt,
    chacha20Poly1305Decrypt: chacha20Poly1305Decrypt,
    argon2id: argon2id
  };
  global.XHCCRYPTO = AC2;
})(typeof window !== 'undefined' ? window : globalThis);
