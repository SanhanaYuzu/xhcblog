/* ===========================================================
   XHC 博客 · 私信桌面提醒（浏览器系统通知）
   - 登录用户任意页面轮询未读私信，弹系统通知 + 提示音
   - localStorage 按最后已通知消息去重，避免多标签页重复弹
   - 暴露 window.XHCDM.ask() 供页面请求通知权限
   =========================================================== */
(function () {
  "use strict";

  var CFG = window.XHC_CONFIG || {};
  var SB_URL = CFG.SUPABASE_URL || "https://ckitmwadwtoavnigsxag.supabase.co";
  var ANON = CFG.SUPABASE_ANON_KEY || "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImNraXRtd2Fkd3RvYXZuaWdzeGFnIiwicm9sZSI6ImFub24iLCJpYXQiOjE3ODU0NzIwNjcsImV4cCI6MjEwMTA0ODA2N30.juUoJi66E7Td5Q-QPA-BUoHa7d4iywwDmaj2B7AIpqY";
  if (!window.supabase || !window.supabase.createClient) return;
  var sb = supabase.createClient(SB_URL, ANON);

  var INTERVAL = 20000;           /* 20 秒轮询一次 */
  var timer = null;
  var uid = null;
  var notifiedKey = function () { return "xhc_dm_notified_" + (uid || "x"); };
  var badgeKey = function () { return "xhc_dm_badge_" + (uid || "x"); };

  function lsGet(k) { try { return localStorage.getItem(k); } catch (e) { return null; } }
  function lsSet(k, v) { try { localStorage.setItem(k, v); } catch (e) {} }

  /* 提示音：880Hz 短蜂鸣 */
  function beep() {
    try {
      var Ctx = window.AudioContext || window.webkitAudioContext;
      if (!Ctx) return;
      var ctx = new Ctx();
      var o = ctx.createOscillator(), g = ctx.createGain();
      o.connect(g); g.connect(ctx.destination);
      o.type = "sine"; o.frequency.value = 880;
      g.gain.setValueAtTime(0.001, ctx.currentTime);
      g.gain.exponentialRampToValueAtTime(0.25, ctx.currentTime + 0.02);
      g.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + 0.3);
      o.start(); o.stop(ctx.currentTime + 0.3);
      setTimeout(function () { try { ctx.close(); } catch (e2) {} }, 600);
    } catch (e) {}
  }

  function supported() { return "Notification" in window; }

  function showNotif(title, body, href) {
    try {
      if (!supported() || Notification.permission !== "granted") return false;
      var icon = 'data:image/svg+xml,%3Csvg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"%3E%3Ctext y=".9em" font-size="88"%3E%F0%9F%92%AC%3C/text%3E%3C/svg%3E';
      var n = new Notification(title, { body: body, icon: icon, tag: "xhc-dm" });
      n.onclick = function () {
        try { window.focus(); } catch (e) {}
        if (href) window.location.href = href;
        n.close();
      };
      beep();
      return true;
    } catch (e) { return false; }
  }

  /* 把私信未读数挂到铃铛（app.js 监听 xhc:dmbadge 事件刷新红点） */
  function broadcastBadge(n) {
    try {
      window.dispatchEvent(new CustomEvent("xhc:dmbadge", { detail: { unread: n } }));
    } catch (e) {}
  }

  function poll() {
    if (!uid) return;
    sb.from("messages")
      .select("id, sender_id, content, created_at, sender:profiles!messages_sender_id_fkey(display_name, username)")
      .eq("receiver_id", uid)
      .eq("read", false)
      .order("created_at", { ascending: false })
      .limit(5)
      .then(function (r) {
        if (r.error || !r.data || !r.data.length) { broadcastBadge(0); return; }
        var rows = r.data;
        var last = lsGet(notifiedKey());
        var newest = rows[0];
        /* 有新未读且比上次已通知的更新 → 弹通知 */
        if (newest.created_at && (!last || newest.created_at > last)) {
          var nm = (newest.sender && (newest.sender.display_name || newest.sender.username)) || "有人";
          var body = nm + "：" + (newest.content || "").slice(0, 60);
          var shown = showNotif("💬 新私信", body, "messages.html");
          if (shown) lsSet(notifiedKey(), newest.created_at);
        }
        broadcastBadge(rows.length);
      }).catch(function () {});
  }

  function start() {
    sb.auth.getSession().then(function (sr) {
      var sess = sr && sr.data && sr.data.session;
      if (!sess || !sess.user) return;
      uid = sess.user.id;
      if (timer) clearInterval(timer);
      timer = setInterval(poll, INTERVAL);
      poll();
    }).catch(function () {});
  }

  function ask() {
    return new Promise(function (resolve) {
      if (!supported()) { resolve(false); return; }
      if (Notification.permission === "granted") { resolve(true); return; }
      if (Notification.permission === "denied") { resolve(false); return; }
      Notification.requestPermission().then(function (p) { resolve(p === "granted"); });
    });
  }

  window.XHCDM = { start: start, ask: ask, supported: supported };

  /* 自动启动 */
  if (document.readyState === "complete") start();
  else window.addEventListener("load", start);
})();
