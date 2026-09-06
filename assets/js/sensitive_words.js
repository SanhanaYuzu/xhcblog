/* ============================================================
   XHCDNS · 敏感词检测系统
   - 词库 = 内置兜底词 + Supabase sensitive_words 表（管理员维护）
   - XHCSW.check(text) → 返回命中敏感词数组
   - XHCSW.manage(adminKey) → 管理员词库管理面板（增/删词）
   - 命中拦截点：发文章 / 评论 / 私信（见 app.js、messages.html）
   ============================================================ */
(function () {
  "use strict";

  var CFG = window.XHC_CONFIG || {};
  var SB_URL = CFG.SUPABASE_URL || "https://ckitmwadwtoavnigsxag.supabase.co";
  var ANON = CFG.SUPABASE_ANON_KEY || "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImNraXRtd2Fkd3RvYXZuaWdzeGFnIiwicm9sZSI6ImFub24iLCJpYXQiOjE3ODU0NzIwNjcsImV4cCI6MjEwMTA0ODA2N30.juUoJi66E7Td5Q-QPA-BUoHa7d4iywwDmaj2B7AIpqY";
  var sb = (window.supabase && window.supabase.createClient) ? supabase.createClient(SB_URL, ANON) : null;

  /* 内置兜底词库：基础违规类别，管理员可在面板扩充（表未建时仍可检测） */
  var BUILTIN = [
    "博彩", "六合彩", "时时彩", "百家乐", "网络赌博", "兼职刷单", "刷单", "杀猪盘",
    "裸聊", "援交", "代开发票", "办证刻章", "跑分", "洗钱", "冰毒", "管制刀具"
  ];

  var EXTRA = [];                 /* 线上词库（管理员维护） */
  var CACHE_KEY = "xhc_sw_cache"; /* localStorage 缓存 30 分钟 */
  var CACHE_TTL = 30 * 60 * 1000;

  /* 归一化：小写 + 去所有空白（含全角空格/零宽字符）+ 全角转半角 */
  function normalize(s) {
    return String(s == null ? "" : s)
      .toLowerCase()
      .replace(/[\s\u3000\u00a0\u200b\u200c\u200d]+/g, "")
      .replace(/[\uFF01-\uFF5E]/g, function (c) { return String.fromCharCode(c.charCodeAt(0) - 0xFEE0); });
  }

  /* HTML 富文本 → 纯文本（检测用，防标签干扰/漏检） */
  function plainText(html) {
    try {
      var d = document.createElement("div");
      d.innerHTML = String(html == null ? "" : html);
      return d.textContent || "";
    } catch (e) { return String(html == null ? "" : html); }
  }

  function allWords() { return BUILTIN.concat(EXTRA); }

  /* 检测：返回命中的词数组 */
  function check(text) {
    var t = normalize(plainText(text));
    if (!t) return [];
    var hits = [];
    allWords().forEach(function (w) {
      w = String(w || "").trim();
      if (w && hits.indexOf(w) < 0 && t.indexOf(normalize(w)) >= 0) hits.push(w);
    });
    return hits;
  }

  /* 拉取线上词库（缓存 30 分钟；失败静默，仅用内置词） */
  function loadRemote(cb) {
    if (!sb) { if (cb) cb(); return; }
    try {
      var c = JSON.parse(localStorage.getItem(CACHE_KEY) || "null");
      if (c && c.ts && Date.now() - c.ts < CACHE_TTL) { EXTRA = c.words || []; if (cb) cb(); return; }
    } catch (e) {}
    sb.from("sensitive_words").select("word").eq("active", true).then(function (r) {
      if (!r.error && r.data) {
        EXTRA = r.data.map(function (x) { return x.word; }).filter(Boolean);
        try { localStorage.setItem(CACHE_KEY, JSON.stringify({ ts: Date.now(), words: EXTRA })); } catch (e2) {}
      }
      if (cb) cb();
    }).catch(function () { if (cb) cb(); });
  }

  /* 调 RPC 增删词（需管理员密钥，与现有管理员体系一致） */
  function callRpc(op, word, key, cb) {
    if (!sb) { cb(false, "数据库未连接"); return; }
    sb.rpc("xhc_admin_word", { op: op, word: word, key: key || "" }).then(function (r) {
      if (r.error) { cb(false, r.error.message || "RPC 错误"); return; }
      var d = r.data || {};
      if (d.ok) cb(true, d); else cb(false, d.error === "auth" ? "鉴权失败" : (d.error || "失败"));
    }).catch(function (e) { cb(false, (e && e.message) || "网络错误"); });
  }

  /* 上报敏感词拦截（通知管理员，静默失败） */
  function report(hits, source, content) {
    if (!sb || !hits || !hits.length) return;
    try {
      sb.rpc("xhc_report_sensitive", {
        content: String(content == null ? "" : content).slice(0, 100),
        source: String(source || "未知"),
        word: hits.slice(0, 6).join("、")
      }).then(function () {}).catch(function () {});
    } catch (e) {}
  }

  /* 管理员词库管理面板 */
  function manage(adminKey) {
    var id = "swPanel";
    if (document.getElementById(id)) { document.getElementById(id).style.display = "flex"; return; }
    var panel = document.createElement("div");
    panel.id = id;
    panel.style.cssText = "display:flex;position:fixed;inset:0;z-index:9999;background:rgba(0,0,0,.55);align-items:center;justify-content:center;padding:20px";
    panel.innerHTML =
      '<div style="position:relative;width:520px;max-width:94vw;max-height:84vh;display:flex;flex-direction:column;background:#f8fafc;border-radius:16px;overflow:hidden;box-shadow:0 20px 60px rgba(0,0,0,.35);">' +
      '<div style="display:flex;align-items:center;justify-content:space-between;padding:14px 20px;background:#fff;border-bottom:1px solid rgba(0,0,0,.08);flex:none;">' +
      '<span style="font-weight:700;color:#111827;font-size:15px;">📋 敏感词管理</span>' +
      '<button type="button" id="swClose" style="border:none;background:none;font-size:22px;cursor:pointer;color:#555;padding:4px 8px;border-radius:6px;line-height:1;">×</button>' +
      '</div>' +
      '<div style="flex:1;overflow-y:auto;padding:16px 20px;font-size:13px;" id="swBody">加载中…</div>' +
      '</div>';
    panel.addEventListener("click", function (e) { if (e.target === panel) panel.style.display = "none"; });
    panel.querySelector("#swClose").addEventListener("click", function () { panel.style.display = "none"; });
    document.body.appendChild(panel);
    render();

    function render() {
      var body = document.getElementById("swBody");
      if (!body) return;
      function esc(s) { return String(s == null ? "" : s).replace(/[&<>"']/g, function (m) { return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[m]; }); }
      body.innerHTML =
        '<div style="display:flex;gap:8px;margin-bottom:14px;">' +
        '<input id="swNewWord" placeholder="输入要拦截的敏感词，回车添加" style="flex:1;padding:9px 12px;border:1px solid #e2e8f0;border-radius:10px;outline:none;font-size:13px;background:#fff;color:#111827;">' +
        '<button id="swAdd" style="border:none;background:#1a73e8;color:#fff;padding:0 18px;border-radius:10px;font-size:13px;font-weight:700;cursor:pointer;">添加</button>' +
        '</div>' +
        '<div style="font-size:12px;color:#9ca3af;margin-bottom:10px;">当前词库 ' + (BUILTIN.length + EXTRA.length) + ' 词 · 命中后发文章 / 评论 / 私信将被拦截并提示</div>' +
        '<div id="swList"></div>' +
        '<div style="margin-top:16px;padding-top:14px;border-top:1px solid #e2e8f0;">' +
        '<div style="font-size:13px;font-weight:700;color:#111827;margin-bottom:4px;">🔔 拦截通知管理员</div>' +
        '<div style="font-size:12px;color:#9ca3af;margin-bottom:8px;">配置后，每次有人发布内容被敏感词拦截，都会给你发一条站内通知（铃铛红点可见）。</div>' +
        '<div style="display:flex;gap:8px;">' +
        '<input id="swAdminUid" placeholder="管理员账号 ID（UUID）" style="flex:1;padding:9px 12px;border:1px solid #e2e8f0;border-radius:10px;outline:none;font-size:12px;background:#fff;color:#111827;">' +
        '<button id="swAdminMe" style="border:none;background:#f1f5f9;color:#111827;padding:0 14px;border-radius:10px;font-size:12px;font-weight:600;cursor:pointer;flex:none;">用当前账号</button>' +
        '<button id="swAdminSave" style="border:none;background:#16a34a;color:#fff;padding:0 16px;border-radius:10px;font-size:12px;font-weight:700;cursor:pointer;flex:none;">保存</button>' +
        '</div>' +
        '<div id="swAdminState" style="font-size:12px;margin-top:8px;color:#9ca3af;">状态：查询中…</div>' +
        '</div>';
      var list = document.getElementById("swList");
      var rows = [];
      EXTRA.forEach(function (w) { rows.push({ w: w, builtin: false }); });
      BUILTIN.forEach(function (w) { if (EXTRA.indexOf(w) < 0) rows.push({ w: w, builtin: true }); });
      if (!rows.length) {
        list.innerHTML = '<div style="text-align:center;color:#9ca3af;padding:20px 0;">词库为空，添加第一个敏感词吧</div>';
      } else {
        list.innerHTML = rows.map(function (r) {
          return '<div style="display:flex;align-items:center;gap:8px;padding:8px 10px;border:1px solid #e2e8f0;border-radius:10px;margin-bottom:7px;background:#fff;">' +
            '<span style="flex:1;word-break:break-all;color:#111827;">' + esc(r.w) + '</span>' +
            (r.builtin
              ? '<span style="font-size:11px;color:#9ca3af;background:#f1f5f9;padding:2px 8px;border-radius:6px;">内置</span>'
              : '<button type="button" data-del="' + esc(r.w) + '" style="border:none;background:#fee2e2;color:#dc2626;padding:4px 12px;border-radius:8px;font-size:12px;cursor:pointer;">删除</button>') +
            '</div>';
        }).join("");
        list.querySelectorAll("[data-del]").forEach(function (btn) {
          btn.addEventListener("click", function () {
            var w = btn.getAttribute("data-del");
            callRpc("remove", w, adminKey, function (ok, err) {
              if (ok) { EXTRA = EXTRA.filter(function (x) { return x !== w; }); render(); toast("已删除：" + w); }
              else toast("删除失败：" + (err || ""), "warn");
            });
          });
        });
      }
      var inp = document.getElementById("swNewWord");
      var addBtn = document.getElementById("swAdd");
      function add() {
        var w = (inp.value || "").trim();
        if (!w) { inp.focus(); return; }
        callRpc("add", w, adminKey, function (ok, err) {
          if (ok) {
            inp.value = "";
            if (EXTRA.indexOf(w) < 0) EXTRA.push(w);
            render();
            toast("已添加：" + w);
          } else toast("添加失败：" + (err || ""), "warn");
        });
      }
      addBtn.addEventListener("click", add);
      inp.addEventListener("keydown", function (e) { if (e.key === "Enter") add(); });

      /* 管理员通知设置：查询当前配置 */
      var stEl = document.getElementById("swAdminState");
      var uidEl = document.getElementById("swAdminUid");
      callRpc("get_admin", "", adminKey, function (ok, d) {
        if (ok && d && d.uid) {
          uidEl.value = d.uid;
          if (stEl) { stEl.textContent = "状态：✅ 已配置，拦截将通知管理员账号（" + d.uid.slice(0, 8) + "…）"; stEl.style.color = "#16a34a"; }
        } else if (stEl) { stEl.textContent = "状态：未配置（拦截时不会通知管理员）"; }
      });
      document.getElementById("swAdminMe").addEventListener("click", function () {
        if (!sb) { toast("数据库未连接", "warn"); return; }
        sb.auth.getUser().then(function (r) {
          var u = r && r.data && r.data.user;
          if (u) { uidEl.value = u.id; toast("已填入当前登录账号 ID"); }
          else toast("请先登录", "warn");
        }).catch(function () { toast("获取账号失败", "warn"); });
      });
      document.getElementById("swAdminSave").addEventListener("click", function () {
        var uid = (uidEl.value || "").trim();
        if (!uid) { toast("请输入管理员账号 ID", "warn"); return; }
        callRpc("set_admin", uid, adminKey, function (ok, d) {
          if (ok) {
            if (stEl) { stEl.textContent = "状态：✅ 已配置，拦截将通知管理员账号（" + uid.slice(0, 8) + "…）"; stEl.style.color = "#16a34a"; }
            toast("已保存，拦截通知将发送给该账号");
          } else toast("保存失败：" + (d && d.error ? (d.error === "auth" ? "鉴权失败" : d.error) : ""), "warn");
        });
      });
    }
  }

  window.XHCSW = { check: check, plain: plainText, load: loadRemote, manage: manage, words: allWords, report: report };

  if (document.readyState === "complete") loadRemote();
  else window.addEventListener("load", function () { loadRemote(); });
})();
