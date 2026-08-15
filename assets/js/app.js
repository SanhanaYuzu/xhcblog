/* ===========================================================
   XHC 博客 · 交互逻辑（Supabase 真实模式 + 本地演示模式）
   -----------------------------------------------------------
   未配置 Supabase key → 演示模式（文章用 data.js、账号/帖子/评论
   存浏览器 localStorage，密码明文仅演示用）。
   配置 key 后 → 真实模式（Supabase auth/数据库/存储）。
   =========================================================== */
(function () {
  "use strict";

  const CFG = window.XHC_CONFIG || {};
  const ARTICLES = window.ARTICLES || [];
  const SITE = window.SITE || {};
  const PER_PAGE = 5;
  const LS = "xhc_demo_";

  /* 动态加载私信桌面提醒脚本（全站任意页面生效，幂等） */
  try {
    if (!document.getElementById("xhc-dm-notify-script")) {
      var _dm = document.createElement("script");
      _dm.id = "xhc-dm-notify-script";
      _dm.src = "assets/js/dm_notify.js";
      _dm.async = true;
      document.head.appendChild(_dm);
    }
  } catch (e) {}

  /* 动态加载敏感词检测脚本（全站任意页面生效，幂等） */
  try {
    if (!document.getElementById("xhc-sw-script")) {
      var _sw = document.createElement("script");
      _sw.id = "xhc-sw-script";
      _sw.src = "assets/js/sensitive_words.js";
      _sw.async = true;
      document.head.appendChild(_sw);
    }
  } catch (e) {}

  /* 敏感词检测工具：命中返回词数组，未命中返回 [] */
  function swCheck(text) {
    if (window.XHCSW) {
      try { return window.XHCSW.check(text); } catch (e) {}
    }
    return [];
  }
  function swHint(hits) {
    return "⛔ 内容包含敏感词：" + hits.slice(0, 6).join("、") + "，请修改后再发布";
  }

  /* ---- OAuth 回跳检测（必须在 createClient 处理 URL 之前抓取）---- */
  function _oauthErr() {
    var e = getParam("error");
    return e ? decodeURIComponent(getParam("error_description") || e) : null;
  }
  var OAUTH_ERROR = _oauthErr();
  var OAUTH_RETURN = OAUTH_ERROR || /[?&]code=/.test(location.search) || /access_token/.test(location.hash);
  /* 回跳地址：回到当前页面（去掉查询/哈希），兼容性最佳，避免写死 /index.html 踩白名单不匹配 */
  function oauthRedirectUrl() { return location.origin + location.pathname; }

  let sb = null;
  if (CFG.enabled && window.supabase && window.supabase.createClient) {
    try { sb = window.supabase.createClient(CFG.SUPABASE_URL, CFG.SUPABASE_ANON_KEY, { auth: { experimental: { passkey: true } } }); }
    catch (e) { console.error("Supabase 初始化失败：", e); sb = null; }
  }
  const REAL = !!sb;

  /* ---------------- 工具 ---------------- */
  function qs(s, r) { return (r || document).querySelector(s); }
  function qsa(s, r) { return Array.prototype.slice.call((r || document).querySelectorAll(s)); }
  function getParam(n) { return new URLSearchParams(location.search).get(n) || ""; }
  function esc(s) {
    return (s == null ? "" : String(s)).replace(/[&<>"']/g, function (m) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[m];
    });
  }
  function fmt(n) { return (n || 0).toLocaleString("en-US"); }
  function uid() { return "u" + Date.now().toString(36) + Math.random().toString(36).slice(2, 8); }
  function nowISO() { return new Date().toISOString(); }
  /* 将 UTC ISO 字符串转为北京时间（UTC+8）的 Date 对象 */
  function bjDate(isoStr) {
    var d = new Date(isoStr + (isoStr.indexOf("Z") === -1 ? "Z" : ""));
    return new Date(d.getTime() + 8 * 3600000);
  }
  /* 北京时间 HH:MM:ss */
  function bjTimeStr(isoStr) {
    if (!isoStr) return "";
    var d = bjDate(isoStr);
    if (isNaN(d.getTime())) d = new Date(); /* 非法日期兜底当前时间，避免 NaN */
    var px = function (x) { return (x < 10 ? "0" : "") + x; };
    return px(d.getHours()) + ":" + px(d.getMinutes());
  }
  /* 北京时间完整日期时间 YYYY-MM-DD HH:MM:SS */
  function bjFullStr(isoStr) {
    if (!isoStr) return "";
    var d = bjDate(isoStr);
    if (isNaN(d.getTime())) d = new Date(); /* 非法日期兜底当前时间，避免 NaN */
    var px = function (x) { return (x < 10 ? "0" : "") + x; };
    return d.getFullYear() + "-" + px(d.getMonth() + 1) + "-" + px(d.getDate()) + " " + px(d.getHours()) + ":" + px(d.getMinutes()) + ":" + px(d.getSeconds());
  }
  function dateOf(p) {
    var c = (p && p.created_at) || "";
    if (!c) return (p && p.date) || "";
    var d = bjDate(c);
    if (isNaN(d.getTime())) return (p && p.date) || "";
    var px = function (x) { return (x < 10 ? "0" : "") + x; };
    return d.getFullYear() + "-" + px(d.getMonth() + 1) + "-" + px(d.getDate());
  }
  function withTimeout(p, ms, label) {
    return new Promise(function (resolve, reject) {
      var done = false;
      var t = setTimeout(function () {
        if (!done) { done = true; reject(new Error((label || "请求") + "超时（可能无法连接 Supabase）")); }
      }, ms);
      Promise.resolve(p).then(function (v) {
        if (!done) { done = true; clearTimeout(t); resolve(v); }
      }, function (e) {
        if (!done) { done = true; clearTimeout(t); reject(e); }
      });
    });
  }
  function nowStr() {
    var d = new Date(), p = function (x) { return (x < 10 ? "0" : "") + x; };
    return d.getFullYear() + "-" + p(d.getMonth() + 1) + "-" + p(d.getDate()) + " " + p(d.getHours()) + ":" + p(d.getMinutes());
  }
  function toast(msg, type) {
    var t = document.createElement("div");
    t.className = "toast " + (type || "");
    t.textContent = msg;
    document.body.appendChild(t);
    setTimeout(function () { t.classList.add("show"); }, 10);
    setTimeout(function () { t.classList.remove("show"); setTimeout(function () { t.remove(); }, 300); }, 2600);
  }

  /* ---- 夜间模式 ---- */
  function applyTheme() {
    var saved = localStorage.getItem("xhc_theme");
    if (saved === "dark") document.body.classList.add("dark");
    else document.body.classList.remove("dark");
    updateThemeBtn();
    swapLogo();
  }
  function toggleTheme() {
    var isDark = document.body.classList.toggle("dark");
    localStorage.setItem("xhc_theme", isDark ? "dark" : "light");
    updateThemeBtn();
    swapLogo();
  }
  /* ---- 动效开关 ---- */
  function applyMotion() {
    var saved = localStorage.getItem("xhc_motion");
    if (saved === "off") document.documentElement.classList.add("no-anim");
    else document.documentElement.classList.remove("no-anim");
  }
  function toggleMotion(force) {
    var off = (typeof force === "boolean") ? force : !document.documentElement.classList.contains("no-anim");
    document.documentElement.classList.toggle("no-anim", off);
    localStorage.setItem("xhc_motion", off ? "off" : "on");
    return off;
  }

  /* 夜间模式切换 logo（仅 header + 加载动画，不改头像） */
  function swapLogo() {
    var useDark = document.body.classList.contains("dark");
    var v = "?v=2"; /* 破缓存 */
    /* 根据当前页面目录深度自动计算 ../ 前缀 */
    var parts = location.pathname.split("/");
    var depth = Math.max(0, parts.length - 2); /* 去掉首空串和文件名 */
    var prefix = depth > 0 ? "../".repeat(depth) : "";
    document.querySelectorAll(".site-logo").forEach(function (img) {
      img.src = useDark ? prefix + "assets/images/xhcntgroup-b.png" + v : prefix + "assets/images/xhc-96x96.png" + v;
    });
    document.querySelectorAll(".loader-logo").forEach(function (img) {
      img.src = useDark ? prefix + "assets/images/xhcntgroup-b.png" + v : prefix + "assets/images/loading-logo.png" + v;
    });
    /* 头像区域保持原版不变 */
    var av = qs("#avatarPreview");
    if (av && !av.dataset.originalSrc) { av.dataset.originalSrc = av.src; }
  }
  function updateThemeBtn() {
    var b = qs("#themeToggle");
    if (b) b.textContent = document.body.classList.contains("dark") ? "☀️" : "🌙";
  }

  /* ===========================================================
     数据层 Store（REAL / DEMO 双实现）
     =========================================================== */
  const Store = {
    REAL: REAL,

    /* ---- 演示模式存储 ---- */
    _dget(k, d) { try { return JSON.parse(localStorage.getItem(LS + k) || "null") || d; } catch (e) { return d; } },
    _dset(k, v) { localStorage.setItem(LS + k, JSON.stringify(v)); },
    ensureDemo() {
      if (this._dget("posts", null)) return;
      var posts = ARTICLES.map(function (a) {
        return { id: a.id, user_id: null, title: a.title, summary: a.summary, category: a.category,
          tags: a.tags || [], content: a.content, cover: a.cover || "", views: a.views || 0,
          likes_count: 0, favorites_count: 0,
          created_at: (a.date || "2026-01-01") + "T00:00:00Z", updated_at: nowISO(), author: null };
      });
      this._dset("posts", posts);
      this._dset("comments", []);
      this._dset("users", []);
    },

    /* ---- 会话 ---- */
    async getSession() {
      if (REAL) {
        var r = await sb.auth.getUser();
        if (r.error || !r.data.user) return null;
        var u = r.data.user;
        try {
          var pr = await sb.from("profiles").select("*").eq("id", u.id).single();
          if (pr.data) {
            var meta = u.user_metadata || {};
            u = Object.assign({}, u, {
              display_name: pr.data.display_name || meta.display_name || u.email,
              avatar_url: pr.data.avatar_url || "",
              username: pr.data.username || "",
              bio: pr.data.bio || ""
            });
          }
        } catch (e) { /* 拿不到资料也不影响登录态 */ }
        return u;
      }
      var id = localStorage.getItem(LS + "session");
      if (!id) return null;
      var u = this._dget("users", []).filter(function (x) { return x.id === id; })[0];
      return u || null;
    },
    onChange(cb) {
      if (REAL) {
        sb.auth.onAuthStateChange(function (e, s) {
          var user = s && s.user ? s.user : null;
          if (e === "SIGNED_IN" && OAUTH_RETURN) {
            OAUTH_RETURN = false;
            toast("第三方登录成功，欢迎回来！");
            var am = qs("#authModal"); if (am) am.style.display = "none";
            var pp = "";
            try { pp = sessionStorage.getItem("xhc_pending_provider") || "oauth"; sessionStorage.removeItem("xhc_pending_provider"); } catch (err) { pp = "oauth"; }
            reportLogin(pp);
          }
          cb(user);
        });
      } else { window.addEventListener("xhc-auth", function () { cb(arguments); }); }
    },
    _demoAuthEmit() { window.dispatchEvent(new Event("xhc-auth")); },

    async signUp(email, pwd, meta) {
      if (REAL) {
        return sb.auth.signUp({ email: email, password: pwd, options: { data: { display_name: (meta && meta.display_name) || email.split("@")[0] } } });
      }
      var users = this._dget("users", []);
      if (users.some(function (u) { return u.email === email; })) return { error: { message: "该邮箱已注册" } };
      var u = { id: uid(), email: email, pwd: pwd, display_name: (meta && meta.display_name) || email.split("@")[0],
        username: "user_" + Math.random().toString(36).slice(2, 8), bio: "", avatar_url: "", created_at: nowISO() };
      users.push(u); this._dset("users", users);
      localStorage.setItem(LS + "session", u.id); this._demoAuthEmit();
      return { data: { user: u } };
    },
    async signUpWithPhone(phone, pwd, name) {
      if (REAL) {
        return sb.auth.signUp({ phone: phone, password: pwd, options: { data: { display_name: name || ("用户" + phone.slice(-4)) } } });
      }
      var users = this._dget("users", []);
      if (users.some(function (u) { return u.phone === phone; })) return { error: { message: "该手机号已注册，请直接登录" } };
      var u = { id: uid(), phone: phone, email: "", pwd: pwd, display_name: name || ("用户" + phone.slice(-4)),
        username: "user_" + Math.random().toString(36).slice(2, 8), bio: "", avatar_url: "", created_at: nowISO() };
      users.push(u); this._dset("users", users);
      localStorage.setItem(LS + "session", u.id); this._demoAuthEmit();
      return { data: { user: u } };
    },
    async signInWithPhone(phone, pwd) {
      if (REAL) return sb.auth.signInWithPassword({ phone: phone, password: pwd });
      var u = this._dget("users", []).filter(function (x) { return x.phone === phone && x.pwd === pwd; })[0];
      if (!u) return { error: { message: "手机号或密码错误" } };
      localStorage.setItem(LS + "session", u.id); this._demoAuthEmit();
      return { data: { user: u } };
    },
    async signIn(email, pwd) {
      if (REAL) return sb.auth.signInWithPassword({ email: email, password: pwd });
      var u = this._dget("users", []).filter(function (x) { return x.email === email && x.pwd === pwd; })[0];
      if (!u) return { error: { message: "邮箱或密码错误" } };
      localStorage.setItem(LS + "session", u.id); this._demoAuthEmit();
      return { data: { user: u } };
    },
    async signOut() {
      if (REAL) return sb.auth.signOut();
      localStorage.removeItem(LS + "session"); this._demoAuthEmit();
      return { error: null };
    },
    async deleteAccount() {
      if (REAL) {
        // 真实模式：删除自己的 posts/comments（RLS 保证只能删自己的），再删账号
        var me = await sb.auth.getUser();
        if (me.data && me.data.user) {
          await sb.from("posts").delete().eq("user_id", me.data.user.id);
          await sb.from("comments").delete().eq("user_id", me.data.user.id);
        }
        return sb.auth.admin.deleteUser(me.data.user.id); // 需 service_role，普通用户无权限
      }
      var id = localStorage.getItem(LS + "session");
      var posts = this._dget("posts", []).filter(function (p) { return p.user_id !== id; });
      var comments = this._dget("comments", []).filter(function (c) { return c.user_id !== id; });
      var users = this._dget("users", []).filter(function (u) { return u.id !== id; });
      this._dset("posts", posts); this._dset("comments", comments); this._dset("users", users);
      localStorage.removeItem(LS + "session"); this._demoAuthEmit();
      return { error: null };
    },

    /* ---- 资料 ---- */
    async getProfile(uidv) {
      if (REAL) {
        var r = await sb.from("profiles").select("*").eq("id", uidv).single();
        return r.data || null;
      }
      var u = this._dget("users", []).filter(function (x) { return x.id === uidv; })[0];
      return u || null;
    },
    async updateProfile(uidv, data) {
      if (REAL) return sb.from("profiles").update(data).eq("id", uidv);
      var users = this._dget("users", []);
      users = users.map(function (u) { if (u.id === uidv) { Object.assign(u, data); } return u; });
      this._dset("users", users);
      return { error: null };
    },
    async uploadAvatar(uidv, file) {
      if (REAL) {
        var ext = (file.name.split(".").pop() || "png").toLowerCase();
        var path = uidv + "/avatar." + ext;
        var up = await sb.storage.from("avatars").upload(path, file, { upsert: true });
        if (up.error) return { error: up.error };
        var url = sb.storage.from("avatars").getPublicUrl(path).data.publicUrl;
        return { data: { url: url } };
      }
      // 演示：转 base64（限制小图）
      return new Promise(function (res) {
        var fr = new FileReader();
        fr.onload = function () { res({ data: { url: fr.result } }); };
        fr.onerror = function () { res({ error: { message: "读取失败" } }); };
        fr.readAsDataURL(file);
      });
    },

    /* ---- 文章 ---- */
    async list(opts) {
      opts = opts || {};
      if (REAL) {
        try {
          var q = sb.from("posts").select("*, author:profiles!posts_user_id_fkey(display_name, avatar_url, username)", { count: "exact" });
          if (opts.category) q = q.eq("category", opts.category);
          if (opts.tag) q = q.contains("tags", [opts.tag]);
          if (opts.q) q = q.or("title.ilike.%" + opts.q + "%,summary.ilike.%" + opts.q + "%,category.ilike.%" + opts.q + "%");
          /* 置顶永远在最前：先按 pinned 降序，再按所选排序 */
          q = q.order("pinned", { ascending: false });
          q = (opts.sort === "hot") ? q.order("views", { ascending: false }) : q.order("created_at", { ascending: false });
          var ps = opts.pageSize || PER_PAGE;
          var from = (opts.page - 1) * ps, to = from + ps - 1;
          q = q.range(from, to);
          var r = await withTimeout(q, 8000, "读取文章列表");
          if (r.error) throw r.error;
          return { posts: r.data || [], total: r.count || 0, error: null };
        } catch (e) {
          // 数据表未创建或网络不可达 → 记录错误并回退示例文章
          window.__supabaseReadError = (e && (e.message || e.code)) || String(e);
          console.warn("Supabase 读取失败，回退到示例文章：", window.__supabaseReadError);
        }
      }
      this.ensureDemo();
      var posts = this._dget("posts", []);
      if (opts.category) posts = posts.filter(function (p) { return p.category === opts.category; });
      if (opts.tag) posts = posts.filter(function (p) { return (p.tags || []).indexOf(opts.tag) >= 0; });
      if (opts.q) { var s = opts.q.toLowerCase(); posts = posts.filter(function (p) { return (p.title + p.summary + p.category + (p.tags || []).join(" ")).toLowerCase().indexOf(s) >= 0; }); }
      posts = posts.slice().sort(function (a, b) {
        if (!!a.pinned !== !!b.pinned) return a.pinned ? -1 : 1; /* 置顶优先 */
        return opts.sort === "hot" ? (b.views - a.views) : (b.created_at < a.created_at ? -1 : 1);
      });
      var total = posts.length;
      var pg = opts.page || 1;
      var ps = opts.pageSize || PER_PAGE;
      posts = posts.slice((pg - 1) * ps, (pg - 1) * ps + ps);
      return { posts: posts, total: total, error: null };
    },
    async get(id) {
      if (REAL) {
        try {
          var r = await sb.from("posts").select("*, author:profiles!posts_user_id_fkey(display_name, avatar_url, username)").eq("id", id).single();
          if (r.error) throw r.error;
          return { post: r.data, error: null };
        } catch (e) {
          var m = (e && e.message) || "";
          // 仅在后端真的不可用（表未建 / 网络）时回退示例文章，避免空白页；
          // 若是“文章不存在 / 关系解析”等其它错误，则如实返回 null。
          if (/relation|does not exist|42P01|Failed to fetch|fetch failed|network|timeout|could not find a relationship/i.test(m)) {
            console.warn("Supabase 不可用，回退示例文章：", m);
          } else {
            console.warn("读取文章失败：", m);
            return { post: null, error: null };
          }
        }
      }
      var p = this._dget("posts", []).filter(function (x) { return x.id === id; })[0] || null;
      return { post: p, error: null };
    },
    async incViews(id) {
      if (REAL) {
        var cur = await sb.from("posts").select("views").eq("id", id).single();
        if (cur.data) await sb.from("posts").update({ views: (cur.data.views || 0) + 1 }).eq("id", id);
      } else {
        var posts = this._dget("posts", []);
        posts = posts.map(function (p) { if (p.id === id) p.views = (p.views || 0) + 1; return p; });
        this._dset("posts", posts);
      }
    },
    async create(data) {
      if (REAL) {
        var me = await sb.auth.getUser();
        data.user_id = me.data.user.id;
        data.created_at = nowISO(); data.updated_at = nowISO();
        var r = await sb.from("posts").insert(data).select().single();
        return r;
      }
      var u = localStorage.getItem(LS + "session");
      var post = Object.assign({ id: uid(), user_id: u, views: 0, created_at: nowISO(), updated_at: nowISO() }, data);
      var posts = this._dget("posts", []); posts.unshift(post); this._dset("posts", posts);
      return { data: post, error: null };
    },
    async update(id, data) {
      if (REAL) { data.updated_at = nowISO(); return sb.from("posts").update(data).eq("id", id); }
      var posts = this._dget("posts", []);
      posts = posts.map(function (p) { if (p.id === id) Object.assign(p, data); return p; });
      this._dset("posts", posts); return { error: null };
    },
    async remove(id) {
      if (REAL) return sb.from("posts").delete().eq("id", id);
      var posts = this._dget("posts", []).filter(function (p) { return p.id !== id; });
      var cs = this._dget("comments", []).filter(function (c) { return c.post_id !== id; });
      this._dset("posts", posts); this._dset("comments", cs);
      return { error: null };
    },
    /* ---- 置顶（仅密码校验通过后调用）---- */
    async pin(id, val) {
      if (REAL) return sb.rpc("set_post_pin", { p_id: id, p_val: !!val });
      var posts = this._dget("posts", []);
      posts = posts.map(function (p) { if (p.id === id) p.pinned = !!val; return p; });
      this._dset("posts", posts); return { error: null };
    },
    async mine() {
      if (REAL) {
        var me = await sb.auth.getUser();
        var r = await sb.from("posts").select("*, author:profiles!posts_user_id_fkey(display_name, avatar_url, username)")
          .eq("user_id", me.data.user.id).order("created_at", { ascending: false });
        return { posts: r.data || [], error: r.error };
      }
      var uid2 = localStorage.getItem(LS + "session");
      var my = this._dget("posts", []).filter(function (p) { return p.user_id === uid2; })
        .sort(function (a, b) { return a.created_at < b.created_at ? 1 : -1; });
      return { posts: my, error: null };
    },

    /* ---- 点赞 / 收藏（REAL：post_likes / post_favorites 表 + SECURITY DEFINER 函数；DEMO：localStorage）---- */
    async like(postId) {
      if (REAL) {
        var r = await sb.rpc("toggle_post_like", { p_id: postId });
        if (r.error) return { error: r.error };
        return { liked: r.data.liked, likes: r.data.likes, error: null };
      }
      var u = localStorage.getItem(LS + "session");
      if (!u) return { error: { message: "请先登录" } };
      var likes = this._dget("likes", {});
      likes[u] = likes[u] || {};
      var liked = !likes[u][postId];
      if (liked) likes[u][postId] = true; else delete likes[u][postId];
      this._dset("likes", likes);
      var posts = this._dget("posts", []).map(function (p) {
        if (p.id === postId) p.likes_count = (p.likes_count || 0) + (liked ? 1 : -1);
        return p;
      });
      this._dset("posts", posts);
      var cur = posts.filter(function (p) { return p.id === postId; })[0] || { likes_count: 0 };
      return { liked: liked, likes: cur.likes_count || 0, error: null };
    },
    async favorite(postId) {
      if (REAL) {
        var r = await sb.rpc("toggle_post_favorite", { p_id: postId });
        if (r.error) return { error: r.error };
        return { favorited: r.data.favorited, favorites: r.data.favorites, error: null };
      }
      var u = localStorage.getItem(LS + "session");
      if (!u) return { error: { message: "请先登录" } };
      var favs = this._dget("favorites", {});
      favs[u] = favs[u] || {};
      var fav = !favs[u][postId];
      if (fav) favs[u][postId] = true; else delete favs[u][postId];
      this._dset("favorites", favs);
      var posts = this._dget("posts", []).map(function (p) {
        if (p.id === postId) p.favorites_count = (p.favorites_count || 0) + (fav ? 1 : -1);
        return p;
      });
      this._dset("posts", posts);
      var cur = posts.filter(function (p) { return p.id === postId; })[0] || { favorites_count: 0 };
      return { favorited: fav, favorites: cur.favorites_count || 0, error: null };
    },
    /* 批量获取当前用户对一组帖子的点赞 / 收藏状态 */
    async getStates(ids) {
      if (!ids || !ids.length) return { map: {}, error: null };
      if (REAL) {
        try {
          var r = await withTimeout(sb.rpc("get_post_states", { p_ids: ids }), 6000, "读取点赞状态");
          if (r.error) throw r.error;
          var map = {};
          (r.data || []).forEach(function (x) { map[x.post_id] = { liked: x.liked, favorited: x.favorited }; });
          return { map: map, error: null };
        } catch (e) {
          console.warn("get_post_states 失败：", e && e.message);
          return { map: {}, error: null };
        }
      }
      var u = localStorage.getItem(LS + "session");
      var lk = (u && (this._dget("likes", {})[u])) || {};
      var fv = (u && (this._dget("favorites", {})[u])) || {};
      var m = {};
      ids.forEach(function (id) { m[id] = { liked: !!lk[id], favorited: !!fv[id] }; });
      return { map: m, error: null };
    },
    /* 当前用户收藏的文章列表 */
    async listFavorites() {
      if (REAL) {
        var me = await sb.auth.getUser();
        var fr = await sb.from("post_favorites").select("post_id").eq("user_id", me.data.user.id);
        var ids = (fr.data || []).map(function (x) { return x.post_id; });
        if (!ids.length) return { posts: [], total: 0, error: null };
        var pr = await sb.from("posts").select("*, author:profiles!posts_user_id_fkey(display_name, avatar_url, username)")
          .in("id", ids).order("created_at", { ascending: false });
        return { posts: pr.data || [], total: (pr.data || []).length, error: pr.error };
      }
      var u = localStorage.getItem(LS + "session");
      var favs = this._dget("favorites", {});
      var set = (u && favs[u]) || {};
      var favIds = Object.keys(set).filter(function (k) { return set[k]; });
      var posts = this._dget("posts", []).filter(function (p) { return favIds.indexOf(p.id) >= 0; })
        .sort(function (a, b) { return a.created_at < b.created_at ? 1 : -1; });
      return { posts: posts, total: posts.length, error: null };
    },

    /* ---- 评论 ---- */
    async listComments(postId) {
      if (REAL) {
        var r = await sb.from("comments").select("*, author:profiles!comments_user_id_fkey(display_name, avatar_url, username)")
          .eq("post_id", postId).order("created_at", { ascending: true });
        return { comments: r.data || [], error: r.error };
      }
      var cs = this._dget("comments", []).filter(function (c) { return c.post_id === postId; })
        .sort(function (a, b) { return a.created_at < b.created_at ? -1 : 1; });
      return { comments: cs, error: null };
    },
    async addComment(postId, content) {
      if (REAL) {
        var me = await sb.auth.getUser();
          var r = await sb.from("comments").insert({ post_id: postId, user_id: me.data.user.id, content: content })
          .select("*, author:profiles!comments_user_id_fkey(display_name, avatar_url, username)").single();
        return r;
      }
      var u = localStorage.getItem(LS + "session");
      var users = this._dget("users", []);
      var me2 = users.filter(function (x) { return x.id === u; })[0];
      var c = { id: uid(), post_id: postId, user_id: u, content: content,
        created_at: nowISO(), author: me2 ? { display_name: me2.display_name, avatar_url: me2.avatar_url, username: me2.username } : null };
      var cs = this._dget("comments", []); cs.push(c); this._dset("comments", cs);
      return { data: c, error: null };
    },
    async removeComment(id) {
      if (REAL) return sb.from("comments").delete().eq("id", id);
      var cs = this._dget("comments", []).filter(function (c) { return c.id !== id; });
      this._dset("comments", cs); return { error: null };
    },

    /* ---- 批量导入示例（seed） ---- */
    async seed(articles, authorId) {
      if (REAL) {
        var existing = await sb.from("posts").select("title");
        var have = (existing.data || []).map(function (p) { return p.title; });
        var rows = articles.filter(function (a) { return have.indexOf(a.title) < 0; }).map(function (a) {
          return { user_id: authorId, title: a.title, summary: a.summary, category: a.category, tags: a.tags || [],
            content: a.content, cover: a.cover || "", views: a.views || 0, created_at: (a.date || "2026-01-01") + "T00:00:00Z" };
        });
        if (!rows.length) return { data: [], error: null, skipped: true };
        return sb.from("posts").insert(rows).select();
      }
      var posts = this._dget("posts", []);
      var added = 0;
      articles.forEach(function (a) {
        if (posts.some(function (p) { return p.title === a.title; })) return;
        posts.unshift({ id: a.id || uid(), user_id: authorId, title: a.title, summary: a.summary, category: a.category,
          tags: a.tags || [], content: a.content, cover: a.cover || "", views: a.views || 0,
          created_at: (a.date || "2026-01-01") + "T00:00:00Z", updated_at: nowISO(), author: null });
        added++;
      });
      this._dset("posts", posts);
      return { data: { added: added }, error: null };
    }
  };

  function authorOf(p) {
    return {
      name: (p.author && p.author.display_name) || SITE.author || "XHC",
      avatar: (p.author && p.author.avatar_url) || SITE.avatar || "assets/images/xhc-96x96.png"
    };
  }
  function dateOf(p) {
    var c = p.created_at || "";
    return c ? c.slice(0, 10) : (p.date || "");
  }

  /* ===========================================================
     UI · 顶栏 / 账户菜单 / 登录注册模态
     =========================================================== */
  async function initHeader() {
    var y = qs("#year"); if (y) y.textContent = new Date().getFullYear();
    /* 工具页面隐藏博客导航和搜索框（不需要文章分类/搜索） */
    if (location.pathname.indexOf("/tools/") !== -1) {
      var nav = qs("#navCats"); if (nav) nav.style.display = "none";
      var sc = qs(".search"); if (sc) sc.style.display = "none";
      var ft = qs("#forumNavLink"); if (ft) ft.style.display = "none";
    }
    var nav = qs("#navCats");
    if (nav) {
      nav.innerHTML = '<a href="index.html">首页</a>';
      var cur = getParam("category") || getParam("q") || getParam("tag");
      if (!cur) { var hl = qs("a", nav); if (hl) hl.classList.add("active"); }
    }
    var si = qs("#searchInput"), sb2 = qs("#searchBtn");
    if (si && sb2) {
      var go = function () { var q = si.value.trim(); location.href = "index.html?q=" + encodeURIComponent(q); };
      sb2.onclick = go;
      si.addEventListener("keydown", function (e) { if (e.key === "Enter") go(); });
    }
    injectAuthUI();
    /* 顶部全局注入「💬 论坛」入口 */
    var hc = qs(".header .container");
    if (hc && !qs("#forumNavLink")) {
      var fl = document.createElement("a");
      fl.id = "forumNavLink"; fl.className = "btn-home"; fl.href = "forum.html";
      fl.textContent = "💬 论坛";
      var home = qs(".btn-home", hc);
      if (home) home.parentNode.insertBefore(fl, home.nextSibling);
      else hc.appendChild(fl);
    }
    /* 顶部全局注入「🌙/☀️ 夜间模式」切换按钮 */
    if (hc && !qs("#themeToggle")) {
      var tbtn = document.createElement("button");
      tbtn.id = "themeToggle"; tbtn.className = "btn-home theme-toggle";
      tbtn.type = "button";
      hc.insertBefore(tbtn, qs("#accountSlot"));
      tbtn.addEventListener("click", toggleTheme);
    }
    /* 未检测到 XHC 浏览器 → 弹窗提示 */
    function showXhcNoInstalled(reason) {
      var msg = reason || "你没有安装 XHC 浏览器，请安装后打开。";
      if (qs("#xhcNoInstMask")) return;
      var mask = document.createElement("div");
      mask.id = "xhcNoInstMask";
      mask.style.cssText = "position:fixed;inset:0;background:rgba(15,23,42,.55);z-index:99999;display:flex;align-items:center;justify-content:center;padding:20px";
      mask.innerHTML = '<div style="background:#fff;border-radius:16px;padding:28px 30px;width:340px;max-width:88vw;box-shadow:0 12px 48px rgba(0,0,0,.28);text-align:center;font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif">' +
        '<div style="font-size:44px;margin-bottom:12px">🖥️</div>' +
        '<div style="font-size:17px;font-weight:700;color:#111827;margin-bottom:10px">未检测到 XHC 浏览器</div>' +
        '<div style="font-size:13.5px;color:#4b5563;line-height:1.7;margin-bottom:20px">' + esc(msg) + '</div>' +
        '<button type="button" style="width:100%;padding:11px;background:#1a73e8;color:#fff;border:none;border-radius:9px;font-size:14px;font-weight:600;cursor:pointer">我知道了</button>' +
        '</div>';
      mask.addEventListener("click", function (ev) {
        if (ev.target === mask) document.body.removeChild(mask);
      });
      mask.querySelector("button").addEventListener("click", function () {
        document.body.removeChild(mask);
      });
      document.body.appendChild(mask);
    }
    /* 顶部全局注入「💬 私信」按钮（原「打开浏览器」按钮已替换为私信） */
    if (hc && !qs("#openDmBtn")) {
      var lb = document.createElement("a");
      lb.id = "openDmBtn"; lb.className = "btn-home";
      lb.href = "messages.html"; lb.textContent = "💬 私信";
      lb.title = "进入私信";
      var slot = qs("#accountSlot", hc);
      if (slot) hc.insertBefore(lb, slot);
      else hc.appendChild(lb);
    }
    /* 顶部全局注入「🔔 通知铃铛」（登录后可见，未读红点） */
    if (hc && !qs("#notifBell")) {
      var nb = document.createElement("button");
      nb.id = "notifBell"; nb.type = "button"; nb.className = "btn-home";
      nb.style.cssText = "position:relative;font-size:15px;line-height:1;";
      nb.innerHTML = "🔔<span id=\"notifDot\" style=\"display:none;position:absolute;top:-2px;right:-6px;min-width:16px;height:16px;padding:0 4px;border-radius:8px;background:#ef4444;color:#fff;font-size:10px;font-weight:700;align-items:center;justify-content:center;box-sizing:border-box;\">0</span>";
      nb.title = "消息通知";
      var nslot = qs("#accountSlot", hc);
      if (nslot) hc.insertBefore(nb, nslot);
      else hc.appendChild(nb);
      nb.addEventListener("click", openNotifPanel);
    }
    /* 把「返回主站」和「💬 论坛」移到主题切换按钮的右侧（紧挨着），最终顺序：search | 🌙 | 返回主站 | 论坛 | 登录/注册 */
    var toggle = qs("#themeToggle", hc);
    var home = qs(".btn-home:not(#forumNavLink):not(#themeToggle)", hc);
    var forum = qs("#forumNavLink", hc);
    if (toggle) {
      if (forum) toggle.parentNode.insertBefore(forum, toggle.nextSibling);
      if (home) toggle.parentNode.insertBefore(home, toggle.nextSibling);
    }
    updateThemeBtn();
    var user = await Store.getSession();
    renderAccount(user);
    Store.onChange(function () { Store.getSession().then(renderAccount); });
  }

  function injectAuthUI() {
    var slot = qs("#accountSlot");
    if (slot && !slot.dataset.done) {
      slot.dataset.done = "1";
      slot.innerHTML = '<a class="btn btn-login" id="loginLink">登录 / 注册</a>';
      qs("#loginLink").addEventListener("click", function () { openAuth(); });
    }
    if (!qs("#authModal")) {
      var m = document.createElement("div");
      m.id = "authModal"; m.className = "modal-mask";
      m.innerHTML =
        '<div class="modal">' +
        '<button class="modal-x" id="authClose">×</button>' +
        '<div class="modal-head">' +
        '<div class="tabs auth-tabs">' +
        '<a data-mode="signin" class="active">登录</a><a data-mode="signup">注册</a>' +
        '</div>' +
        '</div>' +
        '<div class="modal-body">' +
        '<div id="authMsg" class="auth-msg"></div>' +
        '<form id="authForm">' +
        '<input id="authEmail" type="text" placeholder="邮箱或手机号（手机号用密码注册/登录）" required autocomplete="off">' +
        '<input id="authPwd" type="password" placeholder="密码（至少 6 位）" required minlength="6">' +
        '<input id="authName" type="text" placeholder="昵称（注册时可选）" style="display:none">' +
        '<button type="submit" class="btn btn-primary" id="authSubmit">登录</button>' +
        '</form>' +
        '<div class="cf-box" id="cfBox">' +
        '<span class="cf-checkbox" id="cfCheckbox" title="点击完成验证"></span>' +
        '<span class="cf-label" id="cfLabel">我不是机器人</span>' +
        '<span class="cf-badge">XHC<span class="cf-q">?</span></span>' +
        '</div>' +
        '<div class="auth-divider"><span>或</span></div>' +
        '<button class="btn btn-passkey" id="passkeyLogin">' +
        '<svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor" style="vertical-align:-3px;margin-right:6px"><path d="M17.81 7.71 11.46 1.36a1.05 1.05 0 0 0-1.42 0L3.7 7.71A1 1 0 0 0 3.36 9H7v10a3 3 0 0 0 3 3h4a3 3 0 0 0 3-3v-5h2v5a5 5 0 0 1-5 5h-4a5 5 0 0 1-5-5V9H5.14a1 1 0 0 0-.7-1.29 1 1 0 0 0 .36 0z"/></svg>' +
        ' Passkey 通行密钥' +
        '</button>' +
        '<button class="btn btn-github" id="githubLogin">' +
        '<svg width="18" height="18" viewBox="0 0 16 16" fill="currentColor"><path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z"/></svg>' +
        ' GitHub 登录' +
        '<button class="btn btn-microsoft" id="microsoftLogin">' +
        '<svg width="18" height="18" viewBox="0 0 21 21" aria-hidden="true"><rect x="1" y="1" width="9" height="9" fill="#f25022"/><rect x="11" y="1" width="9" height="9" fill="#7fba00"/><rect x="1" y="11" width="9" height="9" fill="#00a4ef"/><rect x="11" y="11" width="9" height="9" fill="#ffb900"/></svg>' +
        ' 微软账户登录' +
        '<button class="btn btn-gitlab" id="gitlabLogin">' +
        '<svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor" style="vertical-align:-3px;margin-right:6px"><path d="M12 1 9.3 9H3.4l4.9 3.6L6.6 21 12 16.9 17.4 21l-1.7-8.4L20.6 9h-5.9L12 1z"/></svg>' +
        ' GitLab 登录' +
        '</button>' +
'<button class="more-toggle" id="moreToggle"><span>邮箱验证码（免密登录）</span><span class="icn">▶</span></button>' +
        '<div class="more-area" id="moreArea">' +
        '<div class="otp-box">' +
        '<div class="otp-row otp-title">📧 邮箱验证码（免密登录，新邮箱自动注册）</div>' +
        '<input id="otpAccount" type="email" placeholder="输入邮箱" autocomplete="off" spellcheck="false" style="width:100%;box-sizing:border-box;margin-bottom:8px">' +
        '<button type="button" class="btn btn-otp" id="otpSend" style="width:100%;margin-bottom:10px">发送验证码</button>' +
        '<input id="otpCode" type="text" placeholder="8 位验证码" inputmode="numeric" maxlength="8" autocomplete="one-time-code" style="width:100%;box-sizing:border-box;margin-bottom:8px">' +
        '<button type="button" class="btn btn-primary" id="otpLogin">验证码登录</button>' +
        '<div class="otp-hint" id="otpHint">新用户输入邮箱，验证通过即自动注册账号</div>' +
        '</div>' +
        '</div>' +
        '<p class="hint" style="margin-top:10px;">' +
        (REAL ? "使用邮箱密码注册登录，数据保存在 Supabase。" : "演示模式：账号数据仅存本浏览器，密码明文，仅供体验。") +
        '</p>' +
        '</div>' +
        '</div>';
document.body.appendChild(m);
      m.addEventListener("click", function (e) { if (e.target === m) closeAuth(); });
      qs("#authClose").addEventListener("click", closeAuth);
      /* ---- 验证码登录 / 微信 / QQ（国内常用） ---- */
      (function () {
        var st = document.createElement("style");
        st.textContent =
          ".otp-box{margin:10px 0 2px;display:flex;flex-direction:column;gap:8px}" +
          ".otp-row{display:flex;gap:8px;align-items:center}" +
          ".otp-row input{flex:1 1 auto;min-width:0}" +
          ".otp-row button{flex:0 0 auto;flex-shrink:0;width:auto}" +
          ".otp-sel{flex:1;height:38px;border:1px solid #d8dee6;border-radius:8px;padding:0 10px;font-size:14px;background:#fff;color:#2b3440;outline:none}" +
          ".btn-otp{background:#10b981;color:#fff;border:none;border-radius:8px;padding:11px;height:auto;cursor:pointer;font-size:14px;white-space:nowrap}" +
          ".btn-otp:disabled{opacity:.6;cursor:default}" +
          ".otp-hint{font-size:12px;color:#8c959f;margin:2px 0 4px}" +
          ".btn-wechat{background:#07c160 !important;color:#fff !important}" +
          ".btn-passkey,.btn-github,.btn-microsoft,.btn-gitlab{width:100%}" +
          ".btn-passkey{background:#202124 !important;color:#fff !important;margin-top:10px}" +
          ".btn-passkey:hover{background:#000 !important}" +
          ".btn-gitlab{background:#fc6d26 !important;color:#fff !important;margin-top:10px}" +
          ".btn-github{margin-top:10px}" +
          ".btn-microsoft{margin-top:10px}" +
".btn-qq{background:#12b7f5 !important;color:#fff !important}" +
          ".otp-title{font-size:13px;color:#6b7280;font-weight:600}" +
          ".modal-head{padding:16px 22px 8px;border-bottom:1px solid #eef0f4;flex:none}" +
          ".modal-body{flex:1 1 auto;overflow-y:auto;overflow-x:hidden;padding:14px 22px 18px;-webkit-overflow-scrolling:touch}" +
          ".modal-foot{padding:0 22px 16px;flex:none}" +
          ".more-toggle{display:flex;align-items:center;justify-content:space-between;padding:10px 12px;background:#f7f8fa;border:1px solid #e2e8f0;border-radius:8px;color:#5f6368;font-size:13px;cursor:pointer;margin:8px 0;width:100%}" +
          ".more-toggle:hover{background:#eef1f5}" +
          ".more-toggle .icn{transition:transform .2s}" +
          ".more-toggle.open .icn{transform:rotate(90deg)}" +
          ".more-area{max-height:0;overflow:hidden;transition:max-height .25s ease}" +
          ".more-area.open{max-height:520px}" +
          ".cf-box{display:flex;align-items:center;gap:10px;margin:12px 0 6px;padding:12px 14px;background:#f9fafb;border:1px solid #e5e7eb;border-radius:8px;position:relative;user-select:none;cursor:default}" +
          ".cf-box.ok{background:#f0fdf4;border-color:#86efac}" +
          ".cf-checkbox{width:24px;height:24px;border:2px solid #cbd5e1;border-radius:5px;flex:none;cursor:pointer;position:relative;background:#fff;box-sizing:border-box}" +
          ".cf-checkbox:hover{border-color:#94a3b8}" +
          ".cf-checkbox.loading{border-color:#f59e0b}" +
          ".cf-checkbox.loading::after{content:'';position:absolute;inset:5px;border:2px solid transparent;border-top-color:#f59e0b;border-radius:50%;animation:cfspin .8s linear infinite}" +
          ".cf-checkbox.ok{border-color:#22c55e;background:#22c55e}" +
          ".cf-checkbox.ok::after{content:'✓';position:absolute;inset:0;display:flex;align-items:center;justify-content:center;color:#fff;font-size:15px;font-weight:700}" +
          ".cf-label{font-size:14px;color:#374151}" +
          ".cf-badge{position:absolute;right:12px;top:10px;display:flex;align-items:center;gap:4px;font-size:11px;font-weight:700;color:#6b7280;letter-spacing:.5px}" +
          ".cf-q{width:16px;height:16px;border:1.5px solid #9ca3af;border-radius:50%;display:inline-flex;align-items:center;justify-content:center;font-size:10px;color:#9ca3af}" +
          "@keyframes cfspin{to{transform:rotate(360deg)}}" +
          ".modal{display:flex;flex-direction:column;max-height:min(85vh,720px);overflow:hidden;padding:0}";
        document.head.appendChild(st);

        var otpTimer = null;
        function otpHint(t) { var h = qs("#otpHint"); if (h) h.textContent = t; }
        function startCountdown(n) {
          var b = qs("#otpSend"), left = n;
          b.disabled = true; b.textContent = "重新发送(" + left + "s)";
          if (otpTimer) clearInterval(otpTimer);
          otpTimer = setInterval(function () {
            left--;
            if (left <= 0) { clearInterval(otpTimer); b.disabled = false; b.textContent = "发送验证码"; }
            else b.textContent = "重新发送(" + left + "s)";
          }, 1000);
        }
        qs("#otpSend").addEventListener("click", async function () {
          var acc = qs("#otpAccount").value.trim();
          if (!acc) { otpHint("请输入邮箱或手机号"); return; }
          var type = "email";
          if (!REAL) { otpHint("演示模式：验证码固定为 123456"); startCountdown(30); return; }
          var b = qs("#otpSend"); b.disabled = true; b.textContent = "发送中…";
          try {
            if (type === "phone") {
              var r = await sb.auth.signInWithOtp({ phone: acc, options: { shouldCreateUser: true } });
              if (r.error) throw r.error;
              otpHint("验证码已发送至手机（若未收到请先配置短信服务商）");
            } else {
              var r2 = await sb.auth.signInWithOtp({ email: acc, options: { shouldCreateUser: true, emailRedirectTo: window.location.origin + window.location.pathname } });
              if (r2.error) throw r2.error;
              otpHint("验证码已发送至邮箱（请到邮件中查看 6 位验证码）");
            }
            startCountdown(60);
          } catch (e) {
            b.disabled = false; b.textContent = "发送验证码";
            otpHint("发送失败：" + ((e && e.message) || e) + "（邮箱验证码需在 Supabase 邮件模板中显示 Token）");
          }
        });
        qs("#otpLogin").addEventListener("click", async function () {
          var acc = qs("#otpAccount").value.trim(), code = qs("#otpCode").value.trim();
          if (!acc || !code) { otpHint("请填写账号和验证码"); return; }
          var type = "email";
          if (!REAL) {
            if (code !== "123456") { otpHint("演示模式验证码为 123456"); return; }
            closeAuth(); toast("验证码登录成功（演示）"); return;
          }
          var b = qs("#otpLogin"); b.disabled = true;
          try {
            var payload = type === "phone"
              ? { phone: acc, token: code, type: "sms" }
              : { email: acc, token: code, type: "email" };
            var r = await sb.auth.verifyOtp(payload);
            if (r.error) throw r.error;
            closeAuth(); toast("验证码登录成功");
            reportLogin("otp");
          } catch (e) {
            b.disabled = false;
            otpHint("验证失败：" + ((e && e.message) || e));
          }
        });

        /* ---- 滑块人机验证 ---- */
        window.__capOk = false; window.__capExpire = 0;
        window.captchaOk = function () { return !!(window.__capOk && Date.now() < window.__capExpire); };
        window.initCaptcha = function () {
          var box = qs("#cfBox");
          if (!box || box.dataset.init) return;
          box.dataset.init = "1";
          var cb = qs("#cfCheckbox"), label = qs("#cfLabel");
          cb.addEventListener("click", function () {
            if (window.__capOk) return;
            cb.classList.add("loading");
            label.textContent = "验证中…";
            setTimeout(function () {
              window.__capOk = true; window.__capExpire = Date.now() + 5 * 60 * 1000;
              cb.classList.remove("loading");
              cb.classList.add("ok");
              label.textContent = "验证通过";
              box.classList.add("ok");
            }, 600);
          });
        };

        /* ---- 更多登录方式折叠 ---- */
        var mt = qs("#moreToggle"), ma = qs("#moreArea");
        if (mt && ma) {
          mt.addEventListener("click", function () {
            var open = ma.classList.toggle("open");
            mt.classList.toggle("open", open);
          });
        }
      })();
      qsa(".auth-tabs a", m).forEach(function (a) {
        a.addEventListener("click", function () { switchAuthMode(a.dataset.mode); });
      });
      qs("#authForm").addEventListener("submit", function (e) {
        e.preventDefault();
        var email = qs("#authEmail").value.trim(), pwd = qs("#authPwd").value, name = qs("#authName").value.trim();
        var mode = m.dataset.mode || "signin";
        var btn = qs("#authSubmit"); btn.disabled = true; qs("#authMsg").textContent = "处理中…";
        if (mode === "signup" && !captchaOk()) {
          qs("#authMsg").textContent = "请先完成人机验证（拖动滑块到缺口位置）";
          btn.disabled = false; return;
        }
        var isPhone = /^1[3-9]\d{9}$/.test(email);
        var task = isPhone
          ? ((mode === "signup") ? Store.signUpWithPhone(email, pwd, name) : Store.signInWithPhone(email, pwd))
          : ((mode === "signup") ? Store.signUp(email, pwd, { display_name: name }) : Store.signIn(email, pwd));
        Promise.resolve(task).then(function (r) {
          btn.disabled = false;
          if (r.error) { qs("#authMsg").textContent = r.error.message || "操作失败"; return; }
          if (mode === "signup" && REAL && r.data && !r.data.session) {
            qs("#authMsg").textContent = "注册成功！请到邮箱点击确认链接后再登录。"; return;
          }
          closeAuth(); toast(mode === "signup" ? "注册成功，已登录" : "登录成功");
          reportLogin(isPhone ? "phone" : (mode === "signup" ? "signup" : "email"));
        });
      });

      /* GitHub OAuth 登录 */
      qs("#githubLogin").addEventListener("click", function () {
        if (!REAL) { toast("演示模式不支持 GitHub 登录", "warn"); return; }
        var btn = qs("#githubLogin"); btn.disabled = true; btn.textContent = "跳转至 GitHub…";
        try { sessionStorage.setItem("xhc_pending_provider", "github"); } catch (err) {}
        sb.auth.signInWithOAuth({
          provider: "github",
          options: { redirectTo: oauthRedirectUrl() }
        }).catch(function (e) {
          btn.disabled = false;
          btn.innerHTML = '<svg width="18" height="18" viewBox="0 0 16 16" fill="currentColor"><path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z"/></svg> GitHub 登录';
          qs("#authMsg").textContent = "GitHub 登录失败：" + (e.message || "请确认已在 Supabase 启用 GitHub 提供商");
        });
      });

      /* 微软（Microsoft / Azure AD）OAuth 登录 */
      qs("#microsoftLogin").addEventListener("click", function () {
        if (!REAL) { toast("演示模式不支持微软账户登录", "warn"); return; }
        var btn = qs("#microsoftLogin"); btn.disabled = true; btn.textContent = "跳转至微软账户…";
        try { sessionStorage.setItem("xhc_pending_provider", "azure"); } catch (err) {}
        sb.auth.signInWithOAuth({
          provider: "azure",
          options: { redirectTo: oauthRedirectUrl() }
        }).catch(function (e) {
          btn.disabled = false;
          btn.innerHTML = '<svg width="18" height="18" viewBox="0 0 21 21" aria-hidden="true"><rect x="1" y="1" width="9" height="9" fill="#f25022"/><rect x="11" y="1" width="9" height="9" fill="#7fba00"/><rect x="1" y="11" width="9" height="9" fill="#00a4ef"/><rect x="11" y="11" width="9" height="9" fill="#ffb900"/></svg> 微软账户登录';
          qs("#authMsg").textContent = "微软账户登录失败：" + (e.message || "请确认已在 Supabase 启用 Azure（Microsoft）提供商");
        });
      });

      /* 通行密钥（Passkey / WebAuthn 无密码登录） */
      qs("#passkeyLogin").addEventListener("click", function () {
        if (!REAL) { toast("演示模式不支持 Passkey", "warn"); return; }
        var btn = qs("#passkeyLogin"); btn.disabled = true; btn.textContent = "正在唤起系统认证…";
        sb.auth.signInWithPasskey().then(function (r) {
          btn.disabled = false; btn.innerHTML = '<svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor" style="vertical-align:-3px;margin-right:6px"><path d="M12 1a7 7 0 0 0-7 7v2H4a2 2 0 0 0-2 2v9a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-9a2 2 0 0 0-2-2h-1V8a7 7 0 0 0-7-7zm-5 9V8a5 5 0 0 1 10 0v2H7zm5 3.5a2.5 2.5 0 0 1 1.5 4.5V21h-3v-3a2.5 2.5 0 0 1 1.5-4.5z"/></svg> 通行密钥登录（Passkey / 刷脸·指纹）';
          if (r.error) { qs("#authMsg").textContent = "Passkey 失败：" + (r.error.message || ""); return; }
          closeAuth(); toast("Passkey 登录成功");
          reportLogin("passkey");
        });
      });

      /* GitLab OAuth 登录 */
      qs("#gitlabLogin").addEventListener("click", function () {
        if (!REAL) { toast("演示模式不支持 GitLab 登录", "warn"); return; }
        var btn = qs("#gitlabLogin"); btn.disabled = true; btn.textContent = "跳转至 GitLab…";
        try { sessionStorage.setItem("xhc_pending_provider", "gitlab"); } catch (err) {}
        sb.auth.signInWithOAuth({
          provider: "gitlab",
          options: { redirectTo: oauthRedirectUrl() }
        }).catch(function (e) {
          btn.disabled = false;
          btn.innerHTML = '<svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor" style="vertical-align:-3px;margin-right:6px"><path d="M12 1 9.3 9H3.4l4.9 3.6L6.6 21 12 16.9 17.4 21l-1.7-8.4L20.6 9h-5.9L12 1z"/></svg> GitLab 登录';
          qs("#authMsg").textContent = "GitLab 登录失败：" + (e.message || "请确认已在 Supabase 启用 GitLab 提供商");
        });
      });
    }
    if (!qs("#accountMenu")) {
      var menu = document.createElement("div");
      menu.id = "accountMenu";
      menu.style.cssText = "display:none;position:fixed;inset:0;z-index:9998;background:rgba(15,23,42,.5);align-items:center;justify-content:center;padding:20px;";
      function item(icon, label, href, act) {
        var body = '<span style="font-size:18px;width:24px;text-align:center;flex:none;">' + icon + '</span>' +
                   '<span style="flex:1;">' + label + '</span>' +
                   '<span style="color:#cbd5e1;font-size:16px;">›</span>';
        return act
          ? '<a href="javascript:void(0)" data-act="' + act + '" style="display:flex;align-items:center;gap:10px;padding:11px 14px;border-radius:11px;text-decoration:none;color:#111827;font-size:14px;font-weight:500;cursor:pointer;">' + body + '</a>'
          : '<a href="' + href + '" style="display:flex;align-items:center;gap:10px;padding:11px 14px;border-radius:11px;text-decoration:none;color:#111827;font-size:14px;font-weight:500;">' + body + '</a>';
      }
      function sep() { return '<div style="height:1px;background:rgba(0,0,0,.06);margin:6px 6px;"></div>'; }
      menu.innerHTML =
        '<div onclick="event.stopPropagation()" style="width:380px;max-width:94vw;max-height:82vh;display:flex;flex-direction:column;background:#f8fafc;border-radius:18px;overflow:hidden;box-shadow:0 24px 70px rgba(0,0,0,.3);">' +
          '<div style="display:flex;align-items:center;justify-content:space-between;padding:16px 20px;background:#fff;border-bottom:1px solid rgba(0,0,0,.07);flex:none;">' +
            '<span style="font-weight:700;font-size:15px;color:#111827;">👤 我的账户</span>' +
            '<button type="button" id="accountMenuClose" style="border:none;background:none;font-size:22px;cursor:pointer;color:#888;line-height:1;padding:4px 10px;border-radius:6px;">×</button>' +
          '</div>' +
          '<div style="overflow-y:auto;padding:8px 8px;flex:1;background:#f8fafc;" onclick="event.stopPropagation()">' +
            item("✏️", "写文章", "editor.html") +
            item("📋", "我的帖子", "myposts.html") +
            item("⭐", "我的收藏", "favs.html") +
            sep() +
            item("💬", "论坛", "forum.html") +
            item("🧰", "工具箱", "tools.html") +
            item("⚙️", "设置", "settings.html") +
            item("ℹ️", "关于本站", "about.html") +
            item("🖥️", "登录设备", null, "sessions") +
            item("🔔", "桌面提醒", null, "desktop-notify") +
            item("💬", "私信", "messages.html") +
            item("📊", "我的统计", "stats.html") +
            item("📝", "我的草稿", null, "drafts") +
            item("🎁", "神秘按钮", null, "mystery") +
            (isAdmin() ? sep() + item("🛡️", "管理员模式", null, "admin") + item("👥", "用户管理", "users.html") + item("📋", "敏感词管理", null, "sw-manage") : "") +
            item("📥", "导入示例", "seed.html") +
            sep() +
            '<a href="javascript:void(0)" data-act="logout" style="display:flex;align-items:center;gap:10px;padding:11px 14px;border-radius:11px;text-decoration:none;color:#dc2626;font-size:14px;font-weight:600;cursor:pointer;">' +
              '<span style="font-size:18px;width:24px;text-align:center;flex:none;">🚪</span><span style="flex:1;">注销登录</span>' +
            '</a>' +
          '</div>' +
        '</div>';
      document.body.appendChild(menu);
      /* × 关闭 */
      qs("#accountMenuClose").addEventListener("click", function () { menu.style.display = "none"; });
      /* 内部动作路由 */
      qsa("[data-act]", menu).forEach(function (el) {
        el.addEventListener("click", function (e) {
          e.preventDefault();
          var act = el.getAttribute("data-act");
          menu.style.display = "none";
          if (act === "logout") { Store.signOut().then(function () { toast("已注销"); }); }
          else if (act === "sessions") { openSessionsPanel(); }
          else if (act === "drafts") { openDraftsPanel(); }
          else if (act === "desktop-notify") {
            if (window.XHCDM) {
              window.XHCDM.ask().then(function (ok) {
                if (ok) toast("✅ 已开启桌面提醒，收到私信会弹系统通知");
                else if (!window.XHCDM.supported()) toast("当前浏览器不支持桌面通知");
                else toast("⚠️ 通知权限被拒绝，请在浏览器设置中允许本站通知");
              });
            } else {
              toast("桌面提醒脚本未加载，请刷新页面");
            }
          }
          else if (act === "mystery") { openMysteryBox(); }
          else if (act === "sw-manage") {
            requireAdminThen(function () {
              if (window.XHCSW) window.XHCSW.manage(ADMIN_PASSWORD);
              else toast("敏感词脚本未加载，请刷新页面", "warn");
            });
          }
          else if (act === "admin") { showAdminLogin(); }
        });
      });
      /* 点击遮罩关闭 */
      menu.addEventListener("click", function (e) { if (e.target === menu) menu.style.display = "none"; });
      /* ESC 关闭 */
      document.addEventListener("keydown", function accEsc(e) { if (e.key === "Escape" && menu.style.display !== "none") menu.style.display = "none"; });
    }
  }

  /* 通知：点赞/收藏/评论时通知文章作者 */
  async function notifyAuthor(postId, type, extra) {
    try {
      var me = await sb.auth.getUser();
      if (!me || !me.data || !me.data.user) return;
      var pr = await sb.from("posts").select("user_id, title").eq("id", postId).single();
      if (pr.error || !pr.data || !pr.data.user_id) return;
      if (pr.data.user_id === me.data.user.id) return;
      var t = (pr.data.title || "").slice(0, 30);
      var content = "";
      if (type === "like") content = "👍 赞了你的文章《" + t + "》";
      else if (type === "favorite") content = "⭐ 收藏了你的文章《" + t + "》";
      else if (type === "comment") content = "💬 评论了你的文章《" + t + "》：" + (extra || "").slice(0, 40);
      if (!content) return;
      await sb.from("notifications").insert({ user_id: pr.data.user_id, actor_id: me.data.user.id, post_id: postId, type: type, content: content });
    } catch (e) {}
  }

  /* 通知铃铛：注入 + 下拉 + 未读数（通知 + 私信未读合并） */
  function bellUnreadCount() {
    try {
      sb.auth.getSession().then(function (sr) {
        var sess = sr && sr.data && sr.data.session;
        var b = qs("#notifBell");
        if (!b) return;
        var dot = qs("#notifDot", b);
        if (!sess) { if (dot) dot.style.display = "none"; return; }
        var p1 = sb.from("notifications").select("id", { count: "exact", head: true }).eq("user_id", sess.user.id).eq("read", false);
        var p2 = sb.from("messages").select("id", { count: "exact", head: true }).eq("receiver_id", sess.user.id).eq("read", false);
        Promise.all([p1, p2]).then(function (rs) {
          var n = 0;
          rs.forEach(function (r) { if (!r.error && r.count != null) n += r.count; });
          if (dot) { dot.style.display = n > 0 ? "flex" : "none"; dot.textContent = n > 99 ? "99+" : String(n); }
        }).catch(function () {});
      }).catch(function () {});
    } catch (e) {}
  }
  /* 新私信到达（dm_notify.js 广播）→ 刷新红点 */
  window.addEventListener("xhc:dmbadge", bellUnreadCount);
  function openNotifPanel() {
    var id = "notifPanel";
    if (qs("#" + id)) { qs("#" + id).style.display = "flex"; return; }
    var panel = document.createElement("div");
    panel.id = id;
    panel.style.cssText = "display:flex;position:fixed;inset:0;z-index:9999;background:rgba(0,0,0,.55);align-items:center;justify-content:center;padding:20px";
    panel.innerHTML =
      '<div style="position:relative;width:480px;max-width:94vw;max-height:80vh;display:flex;flex-direction:column;background:#f8fafc;border-radius:16px;overflow:hidden;box-shadow:0 20px 60px rgba(0,0,0,.35);">' +
      '<div style="display:flex;align-items:center;justify-content:space-between;padding:14px 20px;background:#fff;border-bottom:1px solid rgba(0,0,0,.08);flex:none;">' +
      '<span style="font-weight:700;color:#111827;font-size:15px;">🔔 消息通知</span>' +
      '<span style="display:flex;gap:8px;align-items:center;">' +
      '<button type="button" id="notifReadAll" style="border:none;background:#e8f0fe;color:#1a73e8;padding:6px 12px;border-radius:8px;font-size:12px;cursor:pointer;font-weight:600;">全部已读</button>' +
      '<button type="button" id="notifClose" style="border:none;background:none;font-size:22px;cursor:pointer;color:#555;padding:4px 8px;border-radius:6px;line-height:1;">×</button>' +
      '</span></div>' +
      '<div style="flex:1;overflow-y:auto;padding:16px 20px;font-size:13px;" id="notifBody">加载中…</div></div>';
    panel.addEventListener("click", function (e) { if (e.target === panel) panel.style.display = "none"; });
    panel.querySelector("#notifClose").addEventListener("click", function () { panel.style.display = "none"; });
    panel.querySelector("#notifReadAll").addEventListener("click", function () {
      sb.auth.getSession().then(function (sr) {
        var sess = sr && sr.data && sr.data.session;
        if (!sess) return;
        sb.from("notifications").update({ read: true }).eq("user_id", sess.user.id).eq("read", false)
          .then(function () { loadNotif(); bellUnreadCount(); toast("已全部标记为已读"); });
      });
    });
    document.body.appendChild(panel);
    loadNotif();
  }
  function loadNotif() {
    var body = qs("#notifBody");
    if (!body) return;
    body.innerHTML = "加载中…";
    sb.auth.getSession().then(function (sr) {
      var sess = sr && sr.data && sr.data.session;
      if (!sess) { body.innerHTML = '<div style="text-align:center;color:#9ca3af;padding:30px 0;">未登录</div>'; return; }
      sb.from("notifications").select("*, actor:profiles!notifications_actor_id_fkey(display_name, avatar_url)")
        .eq("user_id", sess.user.id).order("created_at", { ascending: false }).limit(30)
        .then(function (r) {
          var rows = r.data || [];
          if (!rows.length) { body.innerHTML = '<div style="text-align:center;color:#9ca3af;padding:30px 0;">暂无通知</div>'; return; }
          body.innerHTML = rows.map(function (n) {
            var d = new Date(n.created_at);
            var t = isNaN(d.getTime()) ? String(n.created_at) : d.toLocaleString("zh-CN", { hour12: false });
            var nm = (n.actor && (n.actor.display_name || n.actor.username)) || "有人";
            var href = n.post_id ? 'href="article.html?id=' + encodeURIComponent(n.post_id) + '"' : 'href="javascript:void(0)"';
            return '<a ' + href + ' style="display:block;text-decoration:none;padding:10px 12px;border-radius:10px;margin-bottom:8px;background:' + (n.read ? "#f9fafb" : "#eef4ff") + ';border:1px solid rgba(0,0,0,.05);">' +
              '<div style="font-size:13px;color:#111827;">' + esc(n.content || "新通知") + '</div>' +
              '<div style="font-size:11px;color:#9ca3af;margin-top:3px;">' + esc(nm) + ' · ' + esc(t) + (n.read ? "" : ' <span style="color:#1a73e8;font-weight:700;">未读</span>') + '</div>' +
              '</a>';
          }).join("");
          /* 打开面板时自动标记已读（简化：全部已读） */
          sb.from("notifications").update({ read: true }).eq("user_id", sess.user.id).eq("read", false).then(function () { bellUnreadCount(); });
        }).catch(function () { body.innerHTML = "加载失败"; });
    }).catch(function () { body.innerHTML = "加载失败"; });
  }

  /* 登录设备面板：展示 login_sessions，可移除记录 */
  function openSessionsPanel() {
    var id = "sessionsPanel";
    if (qs("#" + id)) { qs("#" + id).style.display = "flex"; refreshSessions(); return; }
    var panel = document.createElement("div");
    panel.id = id;
    panel.style.cssText = "display:flex;position:fixed;inset:0;z-index:9999;background:rgba(0,0,0,.6);align-items:center;justify-content:center;padding:20px";
    panel.innerHTML =
      '<div style="position:relative;width:520px;max-width:94vw;max-height:84vh;display:flex;flex-direction:column;background:#f8fafc;border-radius:16px;overflow:hidden;box-shadow:0 20px 60px rgba(0,0,0,.35);">' +
      '<div style="display:flex;align-items:center;justify-content:space-between;padding:14px 20px;background:#fff;border-bottom:1px solid rgba(0,0,0,.08);flex:none;">' +
      '<span style="font-weight:700;color:#111827;font-size:15px;">🖥️ 登录设备记录</span>' +
      '<button type="button" style="border:none;background:none;font-size:22px;cursor:pointer;color:#555;padding:4px 8px;border-radius:6px;line-height:1;" id="sessionsClose">×</button>' +
      '</div>' +
      '<div style="flex:1;overflow-y:auto;padding:16px 20px;font-size:12px;color:#6b7280;" id="sessionsBody">加载中…</div>' +
      '</div>';
    panel.addEventListener("click", function (e) { if (e.target === panel) panel.style.display = "none"; });
    panel.querySelector("#sessionsClose").addEventListener("click", function () { panel.style.display = "none"; });
    document.addEventListener("keydown", function escS(e) { if (e.key === "Escape" && panel.style.display !== "none") { panel.style.display = "none"; document.removeEventListener("keydown", escS); } });
    document.body.appendChild(panel);
    refreshSessions();
  }

  /* 草稿：保存 / 面板列表 / 恢复 */
  async function saveDraft() {
    try {
      var me = await sb.auth.getUser();
      if (!me || !me.data || !me.data.user) { toast("请先登录", "warn"); openAuth(); return; }
      var data = {
        user_id: me.data.user.id,
        title: (qs("#postTitle") ? qs("#postTitle").value : "").trim(),
        summary: (qs("#postSummary") ? qs("#postSummary").value : "").trim(),
        category: (qs("#postCategory") ? qs("#postCategory").value : "").trim(),
        cover: (qs("#postCover") ? qs("#postCover").value : "").trim(),
        content: (function () {
          var reBody = qs("#reBody");
          if (reBody) return reBody.innerHTML.trim();
          return (qs("#postContent") ? qs("#postContent").value : "").trim();
        })()
      };
      var did = getParam("draft");
      var r = did ? await sb.from("drafts").update(data).eq("id", did).eq("user_id", me.data.user.id)
                   : await sb.from("drafts").insert(data);
      if (r.error) { toast("存草稿失败：" + (r.error.message || ""), "warn"); return; }
      var newId = did || (r.data && r.data[0] && r.data[0].id) || "";
      toast("草稿已保存" + (newId ? "（" + newId.slice(0, 8) + "）" : ""));
    } catch (e) { toast("存草稿失败", "warn"); }
  }
  function openDraftsPanel() {
    var id = "draftsPanel";
    if (qs("#" + id)) { qs("#" + id).style.display = "flex"; loadDrafts(); return; }
    var panel = document.createElement("div");
    panel.id = id;
    panel.style.cssText = "display:flex;position:fixed;inset:0;z-index:9999;background:rgba(0,0,0,.55);align-items:center;justify-content:center;padding:20px";
    panel.innerHTML =
      '<div style="position:relative;width:540px;max-width:94vw;max-height:80vh;display:flex;flex-direction:column;background:#f8fafc;border-radius:16px;overflow:hidden;box-shadow:0 20px 60px rgba(0,0,0,.35);">' +
      '<div style="display:flex;align-items:center;justify-content:space-between;padding:14px 20px;background:#fff;border-bottom:1px solid rgba(0,0,0,.08);flex:none;">' +
      '<span style="font-weight:700;color:#111827;font-size:15px;">📝 我的草稿</span>' +
      '<button type="button" id="draftsClose" style="border:none;background:none;font-size:22px;cursor:pointer;color:#555;padding:4px 8px;border-radius:6px;line-height:1;">×</button></div>' +
      '<div style="flex:1;overflow-y:auto;padding:16px 20px;font-size:13px;" id="draftsBody">加载中…</div></div>';
    panel.addEventListener("click", function (e) { if (e.target === panel) panel.style.display = "none"; });
    panel.querySelector("#draftsClose").addEventListener("click", function () { panel.style.display = "none"; });
    document.body.appendChild(panel);
    loadDrafts();
  }
  function loadDrafts() {
    var body = qs("#draftsBody");
    if (!body) return;
    sb.auth.getSession().then(function (sr) {
      var sess = sr && sr.data && sr.data.session;
      if (!sess) { body.innerHTML = '<div style="text-align:center;color:#9ca3af;padding:30px 0;">未登录</div>'; return; }
      sb.from("drafts").select("*").eq("user_id", sess.user.id).order("updated_at", { ascending: false }).limit(50)
        .then(function (r) {
          var rows = r.data || [];
          if (!rows.length) { body.innerHTML = '<div style="text-align:center;color:#9ca3af;padding:30px 0;">还没有草稿<br><span style="font-size:12px;">在写文章页点「💾 存草稿」即可保存</span></div>'; return; }
          body.innerHTML = rows.map(function (d) {
            var dt = new Date(d.updated_at);
            var t = isNaN(dt.getTime()) ? String(d.updated_at) : dt.toLocaleString("zh-CN", { hour12: false });
            return '<div style="display:flex;align-items:center;gap:10px;padding:11px 13px;background:#fff;border:1px solid rgba(0,0,0,.07);border-radius:11px;margin-bottom:9px;">' +
              '<div style="flex:1;min-width:0;cursor:pointer;" data-open="' + esc(d.id) + '">' +
              '<div style="font-weight:600;font-size:14px;color:#111827;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">' + esc(d.title || "（无标题）") + '</div>' +
              '<div style="font-size:11px;color:#9ca3af;margin-top:2px;">' + esc((d.content || "").slice(0, 40)) + ' · ' + esc(t) + '</div>' +
              '</div>' +
              '<button type="button" data-del="' + esc(d.id) + '" style="flex:none;border:none;background:#fef2f2;color:#dc2626;padding:6px 11px;border-radius:8px;font-size:12px;cursor:pointer;">删除</button>' +
              '</div>';
          }).join("");
          qsa("[data-open]", body).forEach(function (el) {
            el.addEventListener("click", function () { location.href = "editor.html?draft=" + encodeURIComponent(el.getAttribute("data-open")); });
          });
          qsa("[data-del]", body).forEach(function (btn) {
            btn.addEventListener("click", function () {
              if (!confirm("删除这篇草稿？")) return;
              sb.from("drafts").delete().eq("id", btn.getAttribute("data-del")).then(function () { loadDrafts(); toast("已删除"); });
            });
          });
        }).catch(function () { body.innerHTML = "加载失败"; });
    }).catch(function () { body.innerHTML = "加载失败"; });
  }

  function refreshSessions() {
    var body = qs("#sessionsBody");
    if (!body) return;
    body.innerHTML = "加载中…";
    sb.auth.getSession().then(function (sr) {
      var sess = sr && sr.data && sr.data.session;
      if (!sess) { body.innerHTML = '<div class="empty">未登录</div>'; return; }
      fetch(CFG.SUPABASE_URL + "/rest/v1/login_sessions?user_id=eq." + encodeURIComponent(sess.user.id) + "&order=created_at.desc&limit=50", {
        headers: { "apikey": CFG.SUPABASE_ANON_KEY, "Authorization": "Bearer " + sess.access_token }
      }).then(function (r) { return r.json(); }).then(function (rows) {
        if (!Array.isArray(rows) || !rows.length) {
          // 旧登录没有上报记录 → 自动补记当前会话一条（避免空白），并重新查询
          body.innerHTML = '<div style="text-align:center;color:#6b7280;padding:20px 0;">暂无记录，正在补记当前登录…</div>';
          var back = { user_id: sess.user.id, provider: "restored", client: (window.top !== window) ? "网页（内嵌）" : "网页" };
          back.device = (navigator.userAgent || "").slice(0, 300);
          window.__xhcIpLookup(function (ip, region) { back.ip = ip; back.region = region; postBack(); });
          function postBack() {
          fetch(CFG.SUPABASE_URL + "/rest/v1/login_sessions", {
            method: "POST",
            headers: { "Content-Type": "application/json", "apikey": CFG.SUPABASE_ANON_KEY, "Authorization": "Bearer " + sess.access_token, "Prefer": "return=minimal" },
            body: JSON.stringify(back)
          }).then(function (r2) {
            if (r2.ok) { refreshSessions(); return; }
            return r2.text().then(function (t2) {
              body.innerHTML = '<div style="text-align:center;color:#dc2626;padding:24px 0;line-height:1.8;">补记失败（HTTP ' + r2.status + '）<br><span style="font-size:11px;color:#9ca3af;word-break:break-all;">' + esc(t2 || "").slice(0, 150) + '</span></div>';
            });
          }).catch(function () {
            body.innerHTML = '<div style="text-align:center;color:#dc2626;padding:24px 0;">补记失败：网络错误</div>';
          });
          }
          return;
        }
        var provNames = { password: "密码", email: "邮箱密码", phone: "手机号密码", signup: "注册", otp: "邮箱验证码", passkey: "Passkey 通行密钥", github: "GitHub", azure: "微软账户", gitlab: "GitLab", oauth: "第三方", restored: "会话恢复" };
        body.innerHTML = rows.map(function (row) {
          var d = new Date(row.created_at);
          var t = isNaN(d.getTime()) ? String(row.created_at) : d.toLocaleString("zh-CN", { hour12: false });
          var isWeb = (row.client === "网页") && (window.top === window);
          return '<div style="display:flex;align-items:center;gap:12px;padding:12px 14px;background:#fff;border:1px solid rgba(0,0,0,.07);border-radius:12px;margin-bottom:10px;box-shadow:0 1px 3px rgba(0,0,0,.04);">' +
            '<div style="flex:1;min-width:0;">' +
            '<div style="font-weight:600;font-size:14px;color:#111827;">' + esc(row.client || "未知客户端") +
            (isWeb ? ' <span style="font-size:11px;color:#1a73e8;background:#e8f0fe;padding:1px 6px;border-radius:10px;font-weight:700;">当前设备</span>' : "") + '</div>' +
            '<div style="font-size:12px;color:#6b7280;margin-top:3px;">' + esc(provNames[row.provider] || row.provider || "密码") + ' · ' + esc(t) + '</div>' +
            '<div style="font-size:12px;color:#9ca3af;margin-top:2px;word-break:break-all;">📡 设备 IP：' + esc(row.ip || "未知") + (row.region ? ' <span style="color:#cbd5e1;">(' + esc(row.region) + ")</span>" : "") + '</div>' +
            '</div>' +
            '<button type="button" data-sid="' + esc(row.id) + '" style="flex:none;border:none;background:#fef2f2;color:#dc2626;padding:7px 13px;border-radius:8px;font-size:12px;cursor:pointer;font-weight:600;">移除</button>' +
            '</div>';
        }).join("");
        qsa("[data-sid]", body).forEach(function (btn) {
          btn.addEventListener("click", function () {
            var sid = btn.getAttribute("data-sid");
            if (!window.confirm("确定移除这条登录记录？")) return;
            fetch(CFG.SUPABASE_URL + "/rest/v1/login_sessions?id=eq." + encodeURIComponent(sid), {
              method: "DELETE",
              headers: { "apikey": CFG.SUPABASE_ANON_KEY, "Authorization": "Bearer " + sess.access_token }
            }).then(function () { toast("已移除该记录"); refreshSessions(); }).catch(function () { toast("移除失败", "warn"); });
          });
        });
      }).catch(function () { body.innerHTML = "加载失败"; });
    }).catch(function () { body.innerHTML = "加载失败"; });
  }

  function openMysteryBox() {
    var id = "mysteryBox";
    if (qs("#" + id)) { qs("#" + id).style.display = "flex"; return; }
    var box = document.createElement("div");
    box.id = id;
    box.style.cssText = "display:flex;position:fixed;inset:0;z-index:9999;background:rgba(0,0,0,.6);align-items:center;justify-content:center;";
    box.innerHTML =
      '<div style="position:relative;width:95vw;height:92vh;max-width:1200px;background:#fff;border-radius:14px;overflow:hidden;box-shadow:0 20px 60px rgba(0,0,0,.35);">' +
      '<div style="display:flex;align-items:center;justify-content:space-between;padding:10px 18px;background:#f6f8fb;border-bottom:1px solid rgba(0,0,0,.08);">' +
      '<span style="font-weight:700;color:#3498db;font-size:15px;">🎁 神秘按钮</span>' +
      '<button style="border:none;background:none;font-size:22px;cursor:pointer;color:#555;padding:4px 8px;border-radius:6px;line-height:1;" onclick="var b=this.closest(\'[id]\');b.style.display=\'none\';">×</button>' +
      '</div>' +
      '<iframe src="https://onyes5634.github.io/" style="width:100%;height:calc(100% - 46px);border:none;" sandbox="allow-scripts allow-same-origin allow-popups allow-forms"></iframe>' +
      '</div>';
    box.addEventListener("click", function (e) { if (e.target === box) box.style.display = "none"; });
    document.addEventListener("keydown", function escHandler(e) { if (e.key === "Escape") { box.style.display = "none"; document.removeEventListener("keydown", escHandler); } });
    document.body.appendChild(box);
  }

  function switchAuthMode(mode) {
    var m = qs("#authModal"); m.dataset.mode = mode;
    qsa(".auth-tabs a", m).forEach(function (a) { a.classList.toggle("active", a.dataset.mode === mode); });
    qs("#authName").style.display = (mode === "signup") ? "block" : "none";
    qs("#authSubmit").textContent = (mode === "signup") ? "注册并登录" : "登录";
    qs("#authMsg").textContent = "";
    try { initCaptcha(); } catch (e) {}
  }
  function openAuth() { var m = qs("#authModal"); if (m) { m.style.display = "flex"; switchAuthMode("signin"); } }
  function closeAuth() { var m = qs("#authModal"); if (m) m.style.display = "none"; }

  /* IP 地区查询（多 API 兜底，国内任一可达即返回；超时 6s） */
  window.__xhcIpLookup = function (cb) {
    function done(ip, region) { cb(ip || "", region || ""); }
    var APIS = [
      { url: "https://ipwho.is/?lang=zh-CN", ip: function (g) { return (g && g.success) ? (g.ip || "") : ""; }, parts: function (g) { return g ? [g.country, g.region, g.city] : []; } },
      { url: "https://api.ip.sb/geoip",       ip: function (g) { return g ? (g.ip || "") : ""; },       parts: function (g) { return g ? [g.country, g.region, g.city] : []; } },
      { url: "https://ipinfo.io/json",        ip: function (g) { return g ? (g.ip || "") : ""; },       parts: function (g) { return g ? [g.country, g.region, g.city] : []; } },
      { url: "https://freeipapi.com/api/json",ip: function (g) { return g ? (g.ipAddress || "") : ""; }, parts: function (g) { return g ? [g.countryName, g.regionName, g.cityName] : []; } }
    ];
    function chain(i) {
      if (i >= APIS.length) { done("", ""); return; }
      var c = APIS[i];
      fetch(c.url, { signal: AbortSignal.timeout(6000) })
        .then(function (r) { return r.json(); })
        .then(function (g) {
          var ip = c.ip(g);
          var parts = c.parts(g).filter(function (x) { return x; });
          if (ip || parts.length) {
            var uniq = [];
            parts.forEach(function (x) { if (uniq.indexOf(x) < 0) uniq.push(x); });
            done(ip, uniq.join(" "));
          } else chain(i + 1);
        }).catch(function () { chain(i + 1); });
    }
    chain(0);
  };

  /* 登录成功 → 上报登录记录（设备/方式/地区）到 login_sessions */
  function reportLogin(provider, client) {
    provider = provider || "password"; client = client || "网页";
    try {
      sb.auth.getSession().then(function (sr) {
        var sess = sr && sr.data && sr.data.session;
        if (!sess || !sess.user) return;
        var info = { user_id: sess.user.id, provider: provider, client: client };
        function doPost(payload) {
          payload.device = (navigator.userAgent || "").slice(0, 300);
          fetch(CFG.SUPABASE_URL + "/rest/v1/login_sessions", {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              "apikey": CFG.SUPABASE_ANON_KEY,
              "Authorization": "Bearer " + sess.access_token,
              "Prefer": "return=minimal"
            },
            body: JSON.stringify(payload)
          }).catch(function () {});
        }
        try { window.__xhcIpLookup(function (ip, region) { info.ip = ip; info.region = region; doPost(info); }); }
        catch (e) { doPost(info); }
      }).catch(function () {});
    } catch (e) {}
  }

  /* 置顶已合并进管理员模式：非管理员先弹管理员登录，验证成功后执行操作 */
  function requireAdminThen(fn) {
    if (isAdmin()) { fn(); return; }
    toast("请先进入管理员模式", "warn");
    showAdminLogin(fn);
  }

  /* ===========================================================
     管理员系统（密码 admin1234）
     =========================================================== */
  var ADMIN_PASSWORD = "admin1234";
  var ADMIN_KEY = "xhc_admin_auth";

  function isAdmin() {
    return localStorage.getItem(ADMIN_KEY) === "1";
  }

  function showAdminLogin(callback) {
    var m = qs("#adminModal");
    if (!m) {
      m = document.createElement("div");
      m.id = "adminModal"; m.className = "modal-mask";
      m.innerHTML =
        '<div class="modal" style="max-width:380px;">' +
        '<h3 style="margin-top:0;">🛡️ 管理员模式</h3>' +
        '<p style="color:var(--text-2);font-size:13px;margin:4px 0 12px;">输入管理员密码以获取管理权限。</p>' +
        '<input id="adminPwdInput" type="password" style="width:100%;padding:9px 12px;border:1px solid var(--border);border-radius:8px;" placeholder="管理员密码">' +
        '<div id="adminErr" style="color:#dc3545;font-size:13px;min-height:18px;margin:8px 0;"></div>' +
        '<div style="display:flex;gap:10px;justify-content:flex-end;">' +
        '<button class="btn btn-outline" id="adminCancel">取消</button>' +
        '<button class="btn btn-primary" id="adminOk">验证</button>' +
        '</div></div>';
      document.body.appendChild(m);
      m.addEventListener("click", function (e) { if (e.target === m) m.style.display = "none"; });
      qs("#adminCancel", m).addEventListener("click", function () { m.style.display = "none"; });
    }
    m.style.display = "flex";
    var input = qs("#adminPwdInput", m), err = qs("#adminErr", m), ok = qs("#adminOk", m);
    input.value = ""; err.textContent = ""; input.focus();
    var verify = function () {
      if (input.value === ADMIN_PASSWORD) {
        localStorage.setItem(ADMIN_KEY, "1");
        m.style.display = "none";
        toast("✅ 管理员权限已获取");
        if (callback) callback();
      } else {
        err.textContent = "❌ 密码错误，无权访问管理员功能";
      }
    };
    ok.onclick = verify;
    input.onkeydown = function (e) { if (e.key === "Enter") verify(); };
  }

  /* 删除他人帖子 */
  window.adminDeletePost = async function (postId, postTitle) {
    if (!isAdmin()) { showAdminLogin(); return; }
    if (!confirm("⚠️ 管理员操作：确定删除帖子「" + postTitle + "」？\n此操作不可恢复！")) return;
    var r = await sb.rpc("admin_delete_post", { post_id: postId });
    if (r.error) { toast("删除失败：" + r.error.message); }
    else { toast("已删除帖子"); location.reload(); }
  };

  /* 禁言/解禁用户 */
  window.adminToggleBan = async function (userId, userName, ban) {
    if (!isAdmin()) { showAdminLogin(); return; }
    var action = ban ? "禁言" : "解禁";
    if (!confirm("⚠️ 管理员操作：确定" + action + "用户「" + userName + "」？")) return;
    var r = await sb.rpc("admin_toggle_ban", { target_user_id: userId, ban: ban });
    if (r.error) { toast(action + "失败：" + r.error.message); }
    else { toast("已" + action + "「" + userName + "」"); location.reload(); }
  };

  /* 检查当前用户是否被禁言 */
  async function checkBanStatus() {
    if (!REAL) return false; /* 演示模式不禁言 */
    var user = await Store.getSession();
    if (!user) return false;
    try {
      var r = await sb.from("profiles").select("is_banned").eq("id", user.id).single();
      return !!(r.data && r.data.is_banned);
    } catch (e) { return false; }
  }

  /* 公告相关 */
  window.loadAnnouncement = async function () {
    var box = qs("#announcementBar");
    if (!box) return;
    try {
      var r;
      if (REAL) r = await sb.from("announcements").select("*").order("created_at", { ascending: false }).limit(1).single();
      else r = { data: JSON.parse(localStorage.getItem("xhc_announcement") || "null") };
      if (r && r.data && r.data.content) {
        box.innerHTML = '<div class="announcement-inner">' +
          '<span class="announcement-icon">📢</span><div class="announcement-text">' + r.data.content + '</div>' +
          (isAdmin() ? '<button class="announcement-edit" onclick="showAnnouncementEditor()">编辑</button> ' +
            '<button class="announcement-del" onclick="deleteAnnouncement()">删除</button>' : '') +
          '</div>';
        box.style.display = "";
      } else if (isAdmin()) {
        /* 管理员无公告时显示发布入口 */
        box.innerHTML = '<div class="announcement-inner">' +
          '<span class="announcement-icon">📢</span>' +
          '<div class="announcement-text" style="color:#999;font-style:italic;">暂无公告</div>' +
          '<button class="announcement-edit" onclick="showAnnouncementEditor()">发布公告</button>' +
          '</div>';
        box.style.display = "";
      } else {
        box.style.display = "none";
      }
    } catch (e) {
      /* 表不存在时，管理员仍显示入口 */
      if (isAdmin()) {
        box.innerHTML = '<div class="announcement-inner">' +
          '<span class="announcement-icon">📢</span>' +
          '<div class="announcement-text" style="color:#999;font-style:italic;">暂无公告</div>' +
          '<button class="announcement-edit" onclick="showAnnouncementEditor()">发布公告</button>' +
          '</div>';
        box.style.display = "";
      } else {
        box.style.display = "none";
      }
    }
  };

  window.showAnnouncementEditor = function () {
    if (!isAdmin()) { showAdminLogin(showAnnouncementEditor); return; }
    var existingContent = "";
    var annText = qs(".announcement-text");
    if (annText) existingContent = annText.innerHTML;

    var m = qs("#announceEditorModal");
    if (!m) {
      m = document.createElement("div");
      m.id = "announceEditorModal"; m.className = "modal-mask";
      m.innerHTML =
        '<div class="modal" style="max-width:680px;width:92%;">' +
        '<h3 style="margin-top:0;">📢 编辑公告</h3>' +
        '<p style="color:var(--text-2);font-size:13px;margin:4px 0 10px;">支持 HTML 标签。公告将显示在首页顶部。</p>' +
        '<div class="re-toolbar">' +
        '<button type="button" class="re-btn" data-cmd="bold" title="粗体"><b>B</b></button>' +
        '<button type="button" class="re-btn" data-cmd="italic" title="斜体"><i>I</i></button>' +
        '<button type="button" class="re-btn" data-cmd="insertH2" title="标题H2">H2</button>' +
        '<button type="button" class="re-btn" data-cmd="insertCode" title="代码块">&lt;/&gt;</button>' +
        '<button type="button" class="re-btn" data-cmd="insertQuote" title="引用">❝</button>' +
        '<button type="button" class="re-btn" data-cmd="insertLink" title="链接">🔗</button>' +
        '</div>' +
        '<div id="announceEditorBody" contenteditable="true" class="re-body announce-edit-body" style="min-height:180px;padding:14px;font-size:15px;line-height:1.7;"></div>' +
        '<div style="display:flex;gap:10px;justify-content:flex-end;margin-top:16px;">' +
        '<button class="btn btn-outline" id="announceCancel">取消</button>' +
        '<button class="btn btn-primary" id="announceSave">发布公告</button>' +
        '</div></div>';
      document.body.appendChild(m);

      /* 工具栏事件 — 复用富文本逻辑 */
      qsa(".re-btn", m).forEach(function (btn) {
        btn.addEventListener("click", function () {
          var cmd = this.dataset.cmd;
          var body = qs("#announceEditorBody");
          if (cmd === "bold") document.execCommand("bold", false, null);
          else if (cmd === "italic") document.execCommand("italic", false, null);
          else if (cmd === "insertH2") document.execCommand("formatBlock", false, "<h2>");
          else if (cmd === "insertCode") {
            var sel = window.getSelection();
            var txt = sel.toString() || "代码";
            var range = sel.getRangeAt(0);
            var pre = document.createElement("pre");
            pre.innerHTML = "<code>" + esc(txt) + "</code>";
            range.deleteContents();
            range.insertNode(pre);
          } else if (cmd === "insertQuote") {
            document.execCommand("formatBlock", false, "<blockquote>");
          } else if (cmd === "insertLink") {
            var url = prompt("请输入链接地址：", "https://");
            if (url) document.execCommand("createLink", false, url);
          }
          body.focus();
        });
      });

      qs("#announceCancel", m).addEventListener("click", function () { m.style.display = "none"; });
      qs("#announceSave", m).addEventListener("click", async function () {
        var html = qs("#announceEditorBody").innerHTML.trim();
        if (!html || html === "<br>") { toast("公告内容不能为空"); return; }
        var r = REAL
          ? await sb.rpc("admin_upsert_announcement", { ann_content: html })
          : { data: { action: "created" } };
        if (r.error) { toast("保存失败：" + r.error.message); }
        else {
          if (!REAL) localStorage.setItem("xhc_announcement", JSON.stringify({ content: html }));
          toast("✅ 公告已发布");
          m.style.display = "none";
          loadAnnouncement();
        }
      });
    }
    m.style.display = "flex";
    var editorBody = qs("#announceEditorBody");
    editorBody.innerHTML = existingContent || "<p>在此输入公告内容…</p>";
    /* 占位符清除 */
    editorBody.addEventListener("focus", function () {
      if (this.innerHTML === "<p>在此输入公告内容…</p>") this.innerHTML = "";
    }, { once: true });
  };

  window.deleteAnnouncement = async function () {
    if (!confirm("确定删除这条公告？")) return;
    var r;
    if (REAL) {
      var annData = await sb.from("announcements").select("id").order("created_at", { ascending: false }).limit(1).single();
      if (annData.data) r = await sb.rpc("admin_delete_announcement", { ann_id: annData.data.id });
      else r = { error: null };
    } else {
      localStorage.removeItem("xhc_announcement");
      r = { error: null };
    }
    if (r.error) { toast("删除失败：" + r.error.message); }
    else { toast("已删除公告"); loadAnnouncement(); }
  };

  function renderAccount(user) {
    var slot = qs("#accountSlot");
    if (!slot) return;
    if (!user) {
      slot.innerHTML = '<a class="btn btn-login" id="loginLink">登录 / 注册</a>';
      qs("#loginLink").addEventListener("click", openAuth);
      return;
    }
    var name = user.display_name || user.email || "用户";
    var av = user.avatar_url || SITE.avatar || "assets/images/xhc-96x96.png";
    slot.innerHTML =
      '<div class="account">' +
      '<img class="account-ava" src="' + esc(av) + '" alt=""><span class="account-name">' + esc(name) + '</span>' +
      '<span class="caret">▾</span></div>';
    var box = qs(".account", slot);
    var menu = qs("#accountMenu");
    if (box) box.addEventListener("click", function (e) {
      e.stopPropagation();
      menu.style.display = (menu.style.display === "flex") ? "none" : "flex";
    });
  }

  /* 作者资料卡（点击作者打开：资料 + 统计 + 发私信） */
  function openAuthorCard(uid) {
    if (!uid) return;
    var id = "authorCard";
    if (qs("#" + id)) { qs("#" + id).style.display = "flex"; return; }
    var card = document.createElement("div");
    card.id = id;
    card.style.cssText = "display:flex;position:fixed;inset:0;z-index:9999;background:rgba(0,0,0,.55);align-items:center;justify-content:center;padding:20px;";
    card.innerHTML =
      '<div style="position:relative;width:360px;max-width:92vw;background:#fff;border-radius:18px;padding:26px 26px 22px;box-shadow:0 20px 60px rgba(0,0,0,.3);text-align:center;">' +
      '<button type="button" style="position:absolute;top:12px;right:14px;border:none;background:none;font-size:22px;cursor:pointer;color:#888;line-height:1;" onclick="var c=document.getElementById(\'authorCard\');if(c)c.style.display=\'none\';">×</button>' +
      '<div style="width:72px;height:72px;border-radius:50%;margin:4px auto 12px;background:#eef1f5;overflow:hidden;display:flex;align-items:center;justify-content:center;font-size:28px;color:#9aa3af;" id="acAva">?</div>' +
      '<div style="font-size:17px;font-weight:700;color:#111827;" id="acName">加载中…</div>' +
      '<div style="font-size:12px;color:#9ca3af;margin-top:3px;" id="acMeta"></div>' +
      '<div style="font-size:12.5px;color:#6b7280;margin-top:10px;min-height:18px;" id="acBio"></div>' +
      '<div style="display:flex;gap:8px;margin-top:16px;">' +
      '<button type="button" id="acStats" style="flex:1;padding:9px;border:1px solid #e2e8f0;background:#f8fafc;color:#374151;border-radius:9px;font-size:13px;cursor:pointer;font-weight:600;">📊 统计</button>' +
      '<button type="button" id="acMsg" style="flex:1;padding:9px;border:none;background:#1a73e8;color:#fff;border-radius:9px;font-size:13px;cursor:pointer;font-weight:600;">💬 发私信</button>' +
      '</div></div>';
    card.addEventListener("click", function (e) { if (e.target === card) card.style.display = "none"; });
    document.body.appendChild(card);
    sb.from("profiles").select("*, username, display_name, avatar_url, bio, created_at").eq("id", uid).single()
      .then(function (r) {
        var p = r.data;
        if (!p) return;
        var nm = p.display_name || p.username || "用户";
        qs("#acName").textContent = nm;
        qs("#acAva").innerHTML = p.avatar_url ? '<img src="' + esc(p.avatar_url) + '" style="width:100%;height:100%;object-fit:cover;" alt="">' : (nm[0] || "?");
        qs("#acBio").textContent = p.bio || "";
        var cd = new Date(p.created_at);
        qs("#acMeta").textContent = "注册于 " + (isNaN(cd.getTime()) ? "" : cd.toLocaleDateString("zh-CN"));
      }).catch(function () {});
    qs("#acStats").addEventListener("click", function () { location.href = "stats.html?uid=" + encodeURIComponent(uid); });
    qs("#acMsg").addEventListener("click", function () { location.href = "messages.html?to=" + encodeURIComponent(uid); });
  }

  /* ===========================================================
     UI · 首页列表 + 侧栏
     =========================================================== */
  function postCard(p, st) {
    st = st || { liked: false, favorited: false };
    var a = authorOf(p);
    var thumbHtml;
    if (p.cover) {
      var isImg = /^(https?:\/\/|data:image\/)/i.test(p.cover);
      thumbHtml = isImg
        ? '<div class="thumb" style="background:var(--bg);overflow:hidden;"><img src="' + esc(p.cover) + '" alt="封面" style="width:100%;height:100%;object-fit:cover;" loading="lazy"></div>'
        : '<div class="thumb">' + esc(p.cover) + "</div>";
    } else {
      thumbHtml = '<div class="thumb"></div>';
    }
    return '<a class="post card" href="article.html?id=' + encodeURIComponent(p.id) + '">' + thumbHtml +
      '<div class="body">' +
      "<h2>" + (p.pinned ? '<span class="pin-badge">📌置顶</span> ' : "") + esc(p.title) + "</h2>" +
      '<p class="summary">' + esc(p.summary || "") + "</p>" +
      '<div class="meta">' +
      '<span class="cat">' + esc(p.category || "未分类") + "</span>" +
      '<span class="dot"></span><span>📅 ' + dateOf(p) + "</span>" +
      '<span class="dot"></span><span>👁 ' + fmt(p.views) + "</span>" +
      "</div>" +
      '<div class="post-actions">' +
      '<button type="button" class="act-btn like-btn' + (st.liked ? " active" : "") + '" data-like="' + esc(p.id) + '">' +
      '<span class="lk">' + (st.liked ? "❤️ 已赞 " : "👍 点赞 ") + fmt(p.likes_count || 0) + "</span></button>" +
      '<button type="button" class="act-btn fav-btn' + (st.favorited ? " active" : "") + '" data-fav="' + esc(p.id) + '">' +
      '<span class="fv">' + (st.favorited ? "⭐ 已收藏 " : "☆ 收藏 ") + fmt(p.favorites_count || 0) + "</span></button>" +
      "</div>" +
      "</div></a>";
  }

  /* 点赞 / 收藏 按钮委托（绑定在列表容器上，阻止冒泡到文档层以避免误触发页面跳转）*/
  function bindReactions(root) {
    if (!root || root.dataset.reactBound) return;
    root.dataset.reactBound = "1";
    root.addEventListener("click", function (e) {
      var lb = e.target.closest("[data-like]");
      if (lb) { e.preventDefault(); e.stopPropagation(); toggleLike(lb.dataset.like, lb); return; }
      var fb = e.target.closest("[data-fav]");
      if (fb) { e.preventDefault(); e.stopPropagation(); toggleFav(fb.dataset.fav, fb); return; }
    });
  }

  async function toggleLike(postId, btn) {
    var user = await Store.getSession();
    if (!user) { toast("请先登录后再点赞", "warn"); openAuth(); return; }
    if (await checkBanStatus()) { toast("🚫 您已被禁言，无法操作", "warn"); return; }
    var r = await Store.like(postId);
    if (r.error) { toast(r.error.message || "操作失败", "warn"); return; }
    if (btn) {
      btn.classList.toggle("active", r.liked);
      var span = btn.querySelector(".lk");
      if (span) span.textContent = (r.liked ? "❤️ 已赞 " : "👍 点赞 ") + fmt(r.likes);
    }
    toast(r.liked ? "已点赞 👍" : "已取消点赞");
    if (r.liked) notifyAuthor(postId, "like", "");
  }
  async function toggleFav(postId, btn) {
    var user = await Store.getSession();
    if (!user) { toast("请先登录后再收藏", "warn"); openAuth(); return; }
    if (await checkBanStatus()) { toast("🚫 您已被禁言，无法操作", "warn"); return; }
    var r = await Store.favorite(postId);
    if (r.error) { toast(r.error.message || "操作失败", "warn"); return; }
    if (btn) {
      btn.classList.toggle("active", r.favorited);
      var span = btn.querySelector(".fv");
      if (span) span.textContent = (r.favorited ? "⭐ 已收藏 " : "☆ 收藏 ") + fmt(r.favorites);
    }
    toast(r.favorited ? "已收藏 ⭐" : "已取消收藏");
    if (r.favorited) notifyAuthor(postId, "favorite", "");
  }

  function renderPager(total, page, f) {
    var pager = qs("#pager"); if (!pager) return;
    if (total <= 1) { pager.innerHTML = ""; return; }
    function mk(pg, label, cur) {
      var ps = new URLSearchParams();
      if (f.category) ps.set("category", f.category);
      if (f.tag) ps.set("tag", f.tag);
      if (f.q) ps.set("q", f.q);
      if (f.sort) ps.set("sort", f.sort);
      if (pg > 1) ps.set("page", pg);
      return '<a ' + (cur ? 'class="cur"' : "") + ' href="index.html?' + ps.toString() + '">' + label + "</a>";
    }
    var html = mk(Math.max(1, page - 1), "‹ 上一页", false);
    for (var pg = 1; pg <= total; pg++) html += mk(pg, pg, pg === page);
    html += mk(Math.min(total, page + 1), "下一页 ›", false);
    pager.innerHTML = html;
  }

  async function renderSidebar() {
    var sbx = qs("#sidebar"); if (!sbx) return;
    var r = await Store.list({ page: 1 });
    var posts = r.posts || [];
    var cats = {}, tags = {}, hot = posts.slice();
    posts.forEach(function (p) {
      cats[p.category] = (cats[p.category] || 0) + 1;
      (p.tags || []).forEach(function (t) { tags[t] = (tags[t] || 0) + 1; });
    });
    // 侧栏分类/标签用全量（演示取已加载，真实需单独聚合；这里取当前页足够展示）
    var catArr = Object.keys(cats);
    var tagArr = Object.keys(tags);
    hot = hot.sort(function (a, b) { return (b.views || 0) - (a.views || 0); }).slice(0, 5);

    /* 私信快捷卡（深蓝卡片样式，仿 .btn-home 风格） */
    var dmCard = '<div class="card"><div class="card-h"><span class="bar"></span> 私信</div><div class="card-b" style="padding:0;">' +
      '<a href="messages.html" id="sidebarDmBtn" style="display:flex;align-items:center;gap:12px;padding:14px 16px;background:linear-gradient(135deg,#1e40af 0%,#3b82f6 100%);color:#fff;border-radius:0 0 12px 12px;text-decoration:none;font-weight:600;position:relative;transition:opacity .15s;" onmouseover="this.style.opacity=.9" onmouseout="this.style.opacity=1">' +
      '<span style="font-size:22px;background:rgba(255,255,255,.18);width:42px;height:42px;border-radius:10px;display:flex;align-items:center;justify-content:center;flex:none;">💬</span>' +
      '<span style="flex:1;min-width:0;"><div style="font-size:15px;font-weight:700;">我的私信</div><div style="font-size:11px;opacity:.85;margin-top:2px;">查看 / 发起新对话</div></span>' +
      '<span style="font-size:18px;opacity:.7;flex:none;">›</span>' +
      '<span id="sidebarDmDot" style="display:none;position:absolute;top:8px;right:10px;min-width:18px;height:18px;padding:0 5px;border-radius:9px;background:#ef4444;color:#fff;font-size:11px;font-weight:700;align-items:center;justify-content:center;line-height:1;box-sizing:border-box;">0</span>' +
      '</a></div></div>';

    var author = '<div class="card author-card"><div class="card-h"><span class="bar"></span> 站长</div><div class="card-b">' +
      '<img class="ava" src="' + esc("assets/images/master-avatar.png") + '" alt="">' +
      '<div class="name">' + esc(SITE.author || "XHC") + "</div>" +
      '<div class="desc">' + esc(SITE.bio || "") + "</div>" +
      '<div class="links">' + (SITE.links || []).map(function (l) { return '<a href="' + l.url + '" target="_blank">' + esc(l.label) + "</a>"; }).join("") + "</div>" +
      "</div></div>";

    var catCard = '<div class="card"><div class="card-h"><span class="bar"></span> 文章分类 <a class="more" href="index.html">全部</a></div><div class="card-b cat-list">' +
      catArr.map(function (c) { return '<a href="index.html?category=' + encodeURIComponent(c) + '">' + esc(c) + '<span class="n">' + cats[c] + "</span></a>"; }).join("") + "</div></div>";

    var hotCard = '<div class="card"><div class="card-h"><span class="bar"></span> 热门文章</div><div class="card-b hot-list">' +
      hot.map(function (p, i) { return '<a href="article.html?id=' + encodeURIComponent(p.id) + '"><span class="rank">' + (i + 1) + "</span><span>" + esc(p.title) + "</span></a>"; }).join("") + "</div></div>";

    var tagCard = '<div class="card"><div class="card-h"><span class="bar"></span> 标签云</div><div class="card-b tags">' +
      tagArr.map(function (t) { return '<a href="index.html?tag=' + encodeURIComponent(t) + '">' + esc(t) + "</a>"; }).join("") + "</div></div>";

    var clockCard = '<div class="card" id="clockCard"><div class="card-h"><span class="bar"></span> 北京时间</div><div class="card-b" style="text-align:center;padding:14px 0;"><div id="bjClock" style="font-size:28px;font-weight:700;font-family:\'Courier New\',monospace;letter-spacing:2px;color:var(--primary,#2563eb);">--:--:--</div><div style="font-size:12px;color:var(--muted,#888);margin-top:4px;" id="bjDate">----/--/--</div></div></div>';

    sbx.innerHTML = dmCard + author + catCard + hotCard + tagCard + clockCard;
    startBJClock();
    updateSidebarDmDot();
  }

  /* 侧栏私信卡片未读红点（未登录隐藏；登录后实时显示未读私信数） */
  function updateSidebarDmDot() {
    var dot = qs("#sidebarDmDot");
    if (!dot || !sb) return;
    sb.auth.getSession().then(function (sr) {
      var sess = sr && sr.data && sr.data.session;
      if (!sess) { dot.style.display = "none"; return; }
      sb.from("messages").select("id", { count: "exact", head: true }).eq("receiver_id", sess.user.id).eq("read", false)
        .then(function (r) {
          var n = (r.count != null) ? r.count : 0;
          dot.style.display = n > 0 ? "flex" : "none";
          dot.textContent = n > 99 ? "99+" : String(n);
        }).catch(function () { dot.style.display = "none"; });
    }).catch(function () { dot.style.display = "none"; });
  }
  window.addEventListener("xhc:dmbadge", updateSidebarDmDot);

  /* 实时北京时间时钟（每秒更新） */
  function startBJClock() {
    function tick() {
      var el = qs("#bjClock"), de = qs("#bjDate");
      if (!el || !de) return;
      var now = new Date(), px = function (x) { return (x < 10 ? "0" : "") + x; };
      el.textContent = px(now.getHours()) + ":" + px(now.getMinutes()) + ":" + px(now.getSeconds());
      de.textContent = now.getFullYear() + "-" + px(now.getMonth() + 1) + "-" + px(now.getDate()) + " " + ["周日","周一","周二","周三","周四","周五","周六"][now.getDay()];
    }
    tick();
    setInterval(tick, 1000);
  }

  async function renderIndex() {
    if (!qs("#postList")) return;
    loadAnnouncement(); /* 加载公告栏 */
    var category = getParam("category"), tag = getParam("tag"), q = getParam("q").toLowerCase(), sort = getParam("sort") || "latest";
    qsa("#tabs a").forEach(function (a) {
      a.classList.toggle("active", a.dataset.sort === sort);
      var ps = new URLSearchParams(); ps.set("sort", a.dataset.sort);
      if (category) ps.set("category", category);
      if (tag) ps.set("tag", tag);
      if (q) ps.set("q", q);
      a.href = "index.html?" + ps.toString();
    });
    var r = await Store.list({ category: category, tag: tag, q: q, sort: sort, page: parseInt(getParam("page") || "1", 10) });
    /* 真实模式读取失败（网络/防火墙/表未建）→ 明确提示，避免静默空白 */
    if (REAL && window.__supabaseReadError) {
      var readErr = window.__supabaseReadError;
      delete window.__supabaseReadError;
      var eb = qs("#postList");
      var demoHtml = (r.posts && r.posts.length) ? r.posts.map(function (p) { return postCard(p); }).join("") : "";
      if (eb) eb.innerHTML =
        '<div class="empty-state" style="border:1px solid #f1c40f;background:#fff8e1;color:#7a5b00;">' +
        '<div class="big">⚠️</div>' +
        '<p><b>无法连接到数据库（Supabase）</b></p>' +
        '<p style="font-size:13px;">原因通常是网络或防火墙限制，导致浏览器无法访问 <code>supabase.co</code>。<br>' +
        '你的文章数据仍在云端，网络恢复后刷新即可显示。</p>' +
        '<p style="font-size:12px;color:#c0392b;">错误：' + esc(readErr) + '</p></div>' +
        (demoHtml ? '<h3 style="margin:18px 0 10px;font-size:15px;color:var(--text-soft);">以下为示例文章（非你的真实数据）：</h3>' + demoHtml : "");
      loadAnnouncement(); renderSidebar();
      return;
    }
    delete window.__supabaseReadError;
    var list = r.posts || [], total = r.total || 0;

    var ft = qs("#feedTitle"), fc = qs("#feedCount");
    var title = sort === "hot" ? "热门文章" : "最新文章";
    if (category) title = "分类：" + category;
    if (tag) title = "标签：" + tag;
    if (q) title = '搜索：“' + q + '”';
    if (ft) ft.textContent = title;
    if (fc) fc.textContent = "共 " + total + " 篇";

    var totalPages = Math.max(1, Math.ceil(total / PER_PAGE));
    var box = qs("#postList");
    var ids = list.map(function (p) { return p.id; });
    var statesMap = (await Store.getStates(ids)).map || {};
    box.innerHTML = list.length === 0
      ? '<div class="empty-state"><div class="big">🔍</div>没有找到相关文章</div>'
      : list.map(function (p) { return postCard(p, statesMap[p.id]); }).join("");
    bindReactions(box);
    renderPager(totalPages, parseInt(getParam("page") || "1", 10), { category: category, tag: tag, q: q, sort: sort });
    renderSidebar();
  }

  /* ===========================================================
     UI · 文章详情 + 评论
     =========================================================== */
  function bindCodeCopy(scope) {
    qsa("pre .copy", scope).forEach(function (btn) {
      btn.addEventListener("click", function () {
        var code = btn.parentElement.querySelector("code");
        if (code && navigator.clipboard) {
          navigator.clipboard.writeText(code.textContent).then(function () {
            btn.textContent = "已复制"; setTimeout(function () { btn.textContent = "复制"; }, 1500);
          });
        }
      });
    });
  }
  function buildTOC(content) {
    var tocList = qs("#tocList"), tocBox = qs("#toc");
    if (!tocList) return;
    var heads = qsa("h2,h3", content);
    if (heads.length === 0) { if (tocBox) tocBox.style.display = "none"; return; }
    tocList.innerHTML = heads.map(function (h, i) {
      h.id = "h-" + i;
      return '<li class="' + (h.tagName === "H3" ? "h3" : "") + '"><a href="#h-' + i + '" data-id="h-' + i + '">' + esc(h.textContent) + "</a></li>";
    }).join("");
    var links = qsa("a", tocList);
    if ("IntersectionObserver" in window) {
      var obs = new IntersectionObserver(function (entries) {
        entries.forEach(function (e) {
          if (e.isIntersecting) {
            links.forEach(function (l) { l.classList.remove("active"); });
            var act = links.filter(function (l) { return l.dataset.id === e.target.id; })[0];
            if (act) act.classList.add("active");
          }
        });
      }, { rootMargin: "-80px 0px -70% 0px" });
      heads.forEach(function (h) { obs.observe(h); });
    }
    links.forEach(function (l) {
      l.addEventListener("click", function (e) {
        e.preventDefault();
        var t = document.getElementById(l.dataset.id);
        if (t) t.scrollIntoView({ behavior: "smooth" });
      });
    });
  }

  async function renderComments(postId, user) {
    var list = qs("#commentList"), title = qs("#commentTitle");
    if (!list) return;
    var r = await Store.listComments(postId);
    var arr = r.comments || [];
    if (title) title.textContent = "评论 (" + arr.length + ")";
    if (arr.length === 0) {
      list.innerHTML = '<div style="color:var(--text-3);font-size:14px;padding:8px 0;">暂无评论，来抢沙发吧～</div>';
    } else {
      list.innerHTML = arr.map(function (c) {
        var nm = (c.author && c.author.display_name) || "访客";
        var av = (c.author && c.author.avatar_url) || "assets/images/xhc-96x96.png";
        var mine = user && (user.id === c.user_id);
        return '<div class="comment-item">' +
          '<img class="cava" src="' + esc(av) + '" alt="">' +
          '<div class="cbody"><span class="cname">' + esc(nm) + '</span><span class="ctime">' + dateOf(c) + " " + bjTimeStr(c.created_at) + "</span>" +
          (mine ? '<button class="cdel" data-id="' + c.id + '">删除</button>' : "") +
          '<div class="ctext">' + esc(c.content) + "</div></div></div>";
      }).join("");
      qsa(".cdel", list).forEach(function (b) {
        b.addEventListener("click", function () {
          if (!confirm("确定删除这条评论？")) return;
          Store.removeComment(b.dataset.id).then(function () { renderComments(postId, user); });
        });
      });
    }
  }

  async function setupCommentForm(postId, user) {
    var wrap = qs(".comment-form"); if (!wrap) return;
    if (!user) {
      wrap.innerHTML = '<div class="login-hint">请 <a href="javascript:void(0)" id="chLogin">登录</a> 后发表评论。</div>';
      qs("#chLogin").addEventListener("click", openAuth);
      return;
    }
    /* 禁言检查 */
    if (await checkBanStatus()) {
      wrap.innerHTML = '<div class="login-hint" style="color:#dc3545;">🚫 您已被禁言，无法发表评论。</div>';
      return;
    }
    var av = user.avatar_url || SITE.avatar || "assets/images/xhc-96x96.png";
    var nm = user.display_name || user.email || "我";
    wrap.innerHTML =
      '<img class="cava" src="' + esc(av) + '" alt="">' +
      '<div class="cf-right"><textarea id="commentText" placeholder="写下你的评论…"></textarea>' +
      '<div class="row"><button class="submit" id="commentSubmit">发表评论</button></div></div>';
    qs("#commentSubmit").addEventListener("click", function () {
      var ta = qs("#commentText"); var text = ta.value.trim();
      if (!text) { ta.focus(); return; }
      var swHits = swCheck(text);
      if (swHits.length) {
        if (window.XHCSW && window.XHCSW.report) { try { window.XHCSW.report(swHits, "评论", text); } catch (e) {} }
        toast(swHint(swHits), "warn"); ta.focus(); return;
      }
      Store.addComment(postId, text).then(function () {
        ta.value = ""; renderComments(postId, user);
        notifyAuthor(postId, "comment", text);
      });
    });
  }

  async function renderArticle() {
    if (!qs("#articleMain")) return;
    var id = getParam("id");
    var r = await Store.get(id);
    var a = r.post;
    if (!a) {
      qs("#articleMain").innerHTML = '<div class="empty-state"><div class="big">😢</div>文章不存在或已删除<br><a href="index.html" style="color:var(--primary)">返回首页</a></div>';
      return;
    }
    document.title = a.title + " - XHC 博客";
    var au = authorOf(a);
    Store.incViews(id);
    var auEl = qs("#articleMeta [data-au]");
    if (auEl) auEl.addEventListener("click", function () { openAuthorCard(auEl.getAttribute("data-au")); });
    qs("#breadcrumb").innerHTML = '<a href="index.html">首页</a> &gt; <a href="index.html?category=' +
      encodeURIComponent(a.category || "") + '">' + esc(a.category || "未分类") + "</a> &gt; <span>" + esc(a.title) + "</span>";
    qs("#articleTitle").textContent = a.title;
    var cc = 0; var cr = await Store.listComments(id); cc = (cr.comments || []).length;
    qs("#articleMeta").innerHTML =
      '<span style="cursor:pointer;" data-au="' + esc(a.user_id || "") + '" title="查看作者资料">' +
      '<img class="author-ava" src="' + esc(au.avatar) + '" alt="">' +
      "<span>" + esc(au.name) + "</span></span>" +
      '<span class="cat">' + esc(a.category || "未分类") + "</span>" +
      "<span>📅 " + dateOf(a) + "</span><span>👁 " + fmt(a.views) + "</span><span>💬 " + cc + "</span>";
    var content = qs("#articleContent");
    content.innerHTML = a.content || "";
    qs("#articleTags").innerHTML = (a.tags || []).map(function (t) { return '<a href="index.html?tag=' + encodeURIComponent(t) + '">#' + esc(t) + "</a>"; }).join("");

    // 上一篇/下一篇（取全量顺序）
    var lr = await Store.list({ page: 1, pageSize: 1000 });
    var all = lr.posts || [];
    var idx = all.map(function (x) { return x.id; }).indexOf(id);
    var prev = all[idx + 1], next = all[idx - 1];
    qs("#prevNext").innerHTML =
      (prev ? '<a href="article.html?id=' + encodeURIComponent(prev.id) + '"><span class="lbl">← 上一篇</span>' + esc(prev.title) + "</a>" : "<span></span>") +
      (next ? '<a href="article.html?id=' + encodeURIComponent(next.id) + '" style="text-align:right"><span class="lbl">下一篇 →</span>' + esc(next.title) + "</a>" : "<span></span>");

    bindCodeCopy(content);
    if (window.hljs) qsa("pre code", content).forEach(function (b) { window.hljs.highlightElement(b); });
    buildTOC(content);

    var user = await Store.getSession();
    setupCommentForm(id, user);
    renderComments(id, user);

    /* ---- 置顶按钮（管理员权限） + 管理员操作 ---- */
    var act = qs("#articleActions");
    if (act) {
      var states = await Store.getStates([id]);
      var st = (states.map && states.map[id]) || { liked: false, favorited: false };
      var pinned = !!a.pinned;
      var html =
        '<button type="button" class="act-btn like-btn' + (st.liked ? " active" : "") + '" id="likeToggle" data-like="' + esc(id) + '">' +
        '<span class="lk">' + (st.liked ? "❤️ 已赞 " : "👍 点赞 ") + fmt(a.likes_count || 0) + "</span></button>" +
        '<button type="button" class="act-btn fav-btn' + (st.favorited ? " active" : "") + '" id="favToggle" data-fav="' + esc(id) + '">' +
        '<span class="fv">' + (st.favorited ? "⭐ 已收藏 " : "☆ 收藏 ") + fmt(a.favorites_count || 0) + "</span></button>" +
        '<button class="btn btn-outline sm" id="pinToggle" style="margin-left:6px;">' +
        (pinned ? "📌 取消置顶" : "📌 设为置顶") + "</button>";
      /* 管理员：删帖 + 禁言/解禁作者 */
      if (isAdmin()) {
        html += '<button class="btn btn-danger sm" id="adminDelPost" style="margin-left:6px;">🗑️ 删除帖子</button>';
        if (a.author && a.author.id) {
          var isBanned = !!(a.author.is_banned);
          html += '<button class="btn btn-' + (isBanned ? "primary" : "warning") + ' sm" id="adminBanUser" style="margin-left:6px;">' +
            (isBanned ? "✅ 解禁用户" : "🚫 禁言用户") + "</button>";
        }
      }
      act.innerHTML = html;
      bindReactions(act);

      qs("#pinToggle").addEventListener("click", function () {
        if (!user) { toast("请先登录再操作", "warn"); openAuth(); return; }
        requireAdminThen(function () {
          Store.pin(id, !pinned).then(function (res) {
            if (res && res.error) { toast("置顶失败：" + (res.error.message || "错误"), "warn"); return; }
            toast(pinned ? "已取消置顶" : "已置顶 ✓");
            renderArticle();
          });
        });
      });

      /* 管理员删帖 */
      var delBtn = qs("#adminDelPost");
      if (delBtn) delBtn.addEventListener("click", function () {
        adminDeletePost(id, a.title);
      });

      /* 管理员禁言/解禁 */
      var banBtn = qs("#adminBanUser");
      if (banBtn) banBtn.addEventListener("click", function () {
        if (a.author && a.author.id) {
          adminToggleBan(a.author.id, a.author.nickname || a.author.username || "该用户", !isBanned);
        }
      });
    }

    /* 相关推荐文章（按标签匹配，排除当前文章） */
    renderRelated(a);
  }

  async function renderRelated(a) {
    var tags = a.tags || [];
    var currentId = a.id;
    if (tags.length === 0) return;
    var r = await Store.list({ tag: tags[0], page: 1, pageSize: 10 });
    var posts = (r.posts || []).filter(function(p){ return p.id !== currentId; }).slice(0, 4);
    var box = qs("#relatedPosts"), list = qs("#relatedList");
    if (!box || !list || posts.length === 0) return;
    box.style.display = "";
    list.innerHTML = posts.map(function(p){
      return '<a href="article.html?id='+encodeURIComponent(p.id)+'" style="display:flex;gap:12px;padding:10px 14px;border:1px solid var(--border);border-radius:10px;text-decoration:none;color:var(--text);transition:background .15s;align-items:center;" onmouseenter="this.style.background=\'var(--primary-soft)\'" onmouseleave="this.style.background=\'\'">'+
        '<span style="font-size:13px;color:var(--primary);flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">' + esc(p.title) + '</span>'+
        '<span style="font-size:12px;color:var(--text-3);white-space:nowrap;">👁 '+fmt(p.views||0)+' · '+dateOf(p)+'</span>'+
        '</a>';
    }).join("");
  }

  /* ===========================================================
     UI · 写文章
     =========================================================== */
  async function renderEditor() {
    if (!qs("#editorForm")) return;
    var user = await Store.getSession();
    if (!user) { qs("#editorNote").innerHTML = '<div class="note warn">请先 <a href="javascript:void(0)" id="eLogin">登录</a> 后再写文章。</div>'; qs("#eLogin").addEventListener("click", openAuth); return; }
    /* 禁言检查 */
    if (await checkBanStatus()) { qs("#editorNote").innerHTML = '<div class="note error">🚫 您已被禁言，无法发布文章。</div>'; return; }
    var editId = getParam("id");
    if (editId) {
      qs("#editorTitle").textContent = "编辑文章";
      var r = await Store.get(editId);
      var p = r.post;
      if (p) {
        qs("#postTitle").value = p.title || "";
        qs("#postSummary").value = p.summary || "";
        qs("#postCategory").value = p.category || "";
        qs("#postTags").value = (p.tags || []).join(", ");
        qs("#postCover").value = p.cover || "";
        /* 加载正文到富编辑器 */
        var reBody = qs("#reBody");
        if (reBody) { reBody.innerHTML = p.content || ""; }
        else { qs("#postContent").value = p.content || ""; }
        qs("#publishBtn").textContent = "保存修改";
      }
    }
    /* 草稿模式：editor.html?draft=<id> 恢复 */
    var draftId = getParam("draft");
    if (draftId) {
      qs("#editorTitle").textContent = "编辑草稿";
      qs("#editorNote").innerHTML = '<div class="note">📝 正在编辑草稿（保存后仍为草稿，发布后自动删除）</div>';
      try {
        var dres = await sb.from("drafts").select("*").eq("id", draftId).single();
        var dp = dres.data;
        if (dp) {
          qs("#postTitle").value = dp.title || "";
          qs("#postSummary").value = dp.summary || "";
          qs("#postCategory").value = dp.category || "";
          qs("#postCover").value = dp.cover || "";
          var reBody = qs("#reBody");
          if (reBody) { reBody.innerHTML = dp.content || ""; }
          else { qs("#postContent").value = dp.content || ""; }
        }
      } catch (e) {}
    }
    /* 存草稿按钮 */
    var dbBtn = qs("#saveDraftBtn");
    if (dbBtn) dbBtn.addEventListener("click", function () { saveDraft(); });

    qs("#editorForm").addEventListener("submit", function (e) {
      e.preventDefault();
      var data = {
        title: qs("#postTitle").value.trim(),
        summary: qs("#postSummary").value.trim(),
        category: qs("#postCategory").value.trim() || "未分类",
        tags: qs("#postTags").value.split(",").map(function (s) { return s.trim(); }).filter(Boolean),
        cover: (qs("#coverImageUrl") && qs("#coverImageUrl").value) || qs("#postCover").value.trim(),
        content: (function () {
          var reBody = qs("#reBody");
          if (reBody) { var h = reBody.innerHTML.trim(); qs("#postContent").value = h; return h; }
          return qs("#postContent").value.trim();
        })()
      };
      if (!data.title) { toast("请填写标题", "warn"); return; }
      /* 敏感词检测：标题/摘要/标签/正文（正文自动转纯文本） */
      var swRaw = [data.title, data.summary, (data.tags || []).join(" "), data.content].join(" ");
      var swHits = swCheck(swRaw);
      if (swHits.length) {
        if (window.XHCSW && window.XHCSW.report) { try { window.XHCSW.report(swHits, "文章发布", data.title + " " + data.summary); } catch (e) {} }
        toast(swHint(swHits), "warn"); return;
      }
      var btn = qs("#publishBtn"); btn.disabled = true;
      var task = editId ? Store.update(editId, data) : Store.create(data);
      Promise.resolve(task).then(function (res) {
        btn.disabled = false;
        if (res.error) {
          var msg = (res.error.message || res.error.error_description || "保存失败") + "";
          if (msg.indexOf("relation") >= 0 || msg.indexOf("does not exist") >= 0 || msg.indexOf("42P01") >= 0) {
            msg = "数据库表尚未建好，请在 Supabase SQL Editor 中运行 schema.sql 后重试。";
          }
          toast(msg, "warn"); return;
        }
        var newId = editId || (res.data && res.data.id) || "";
        if (!newId) { toast("发布成功但未获取到文章 ID，请刷新首页查看", "warn"); renderIndex(); return; }
        /* 发布成功后清除草稿（本地 + 云端） */
        localStorage.removeItem("xhc_draft");
        var did2 = getParam("draft");
        if (did2) { try { sb.from("drafts").delete().eq("id", did2); } catch (e) {} }
        toast(editId ? "已保存" : "发布成功");
        location.href = "article.html?id=" + encodeURIComponent(newId);
      }).catch(function (err) {
        btn.disabled = false;
        var msg = (err && err.message) + "";
        if (msg.indexOf("relation") >= 0 || msg.indexOf("does not exist") >= 0 || msg.indexOf("42P01") >= 0) {
          msg = "数据库表尚未建好，请在 Supabase SQL Editor 中运行 schema.sql 后重试。";
        }
        toast(msg || "发布失败，请检查网络或确认已运行 schema.sql", "warn");
      });
    });

    /* ---- 封面图片上传 ---- */
    var coverInput = qs("#coverImageInput");
    var coverPreviewWrap = qs("#coverPreviewWrap");
    var coverPreviewImg = qs("#coverPreviewImg");
    if (coverInput) {
      coverInput.addEventListener("change", function () {
        var file = this.files && this.files[0];
        if (!file) return;
        if (file.size > 5 * 1024 * 1024) { toast("封面图片不能超过 5MB", "warn"); return; }
        if (REAL && sb.storage) {
          var ext = file.name.split(".").pop().toLowerCase() || "png";
          var fname = "cover-" + Date.now() + "-" + Math.random().toString(36).slice(2, 8) + "." + ext;
          sb.storage.from("covers").upload(fname, file, { cacheControl: "3600", upsert: false }).then(function (r) {
            if (r.error) { toast("封面上传失败：" + (r.error.message || "未知错误"), "warn"); return; }
            var url = sb.storage.from("covers").getPublicUrl(r.data.path).data.publicUrl;
            qs("#coverImageUrl").value = url;
            var fr = new FileReader();
            fr.onload = function () { coverPreviewImg.src = fr.result; coverPreviewWrap.style.display = "block"; };
            fr.readAsDataURL(file);
            toast("封面上传成功 ✓");
          }).catch(function () { toast("封面上传失败，将使用本地预览", "warn"); });
        } else {
          var dr = new FileReader();
          dr.onload = function () {
            coverPreviewImg.src = dr.result;
            coverPreviewWrap.style.display = "block";
            qs("#coverImageUrl").value = dr.result;
          };
          dr.readAsDataURL(file);
        }
      });
    }

    /* ===========================================================
       富文本编辑器（工具栏 + 文档上传 + 源码切换）
       =========================================================== */
    (function initRichEditor() {
      var reBody = qs("#reBody");
      var reSrc = qs("#reSrc");
      var reToggle = qs("#reToggleHtml");
      if (!reBody) return;

      var isHtmlMode = false;

      /* ---- 工具栏按钮：格式化命令 ---- */
      qsa("[data-cmd]", qs("#reToolbar")).forEach(function (btn) {
        btn.addEventListener("click", function () {
          if (isHtmlMode) { toast("请先切回编辑模式再使用工具栏", "warn"); return; }
          var cmd = this.dataset.cmd;
          reBody.focus();
          switch (cmd) {
            case "bold": document.execCommand("bold", false, null); break;
            case "italic": document.execCommand("italic", false, null); break;
            case "h2":
              document.execCommand("formatBlock", false, "h2"); break;
            case "h3":
              document.execCommand("formatBlock", false, "h3"); break;
            case "code":
              insertHtml("<pre><code>" + (getSelText() || "代码") + "</code></pre>");
              break;
            case "ul":
              document.execCommand("insertUnorderedList", false, null); break;
            case "quote":
              insertHtml("<blockquote>" + (getSelText() || "引用内容") + "</blockquote>");
              break;
          }
          reBody.focus();
        });
      });

      /* ---- 辅助：获取选中文本 / 插入 HTML ---- */
      function getSelText() {
        var s = window.getSelection();
        return s ? s.toString() : "";
      }
      function insertHtml(html) {
        if (window.getSelection && window.getSelection().rangeCount > 0) {
          var r = window.getSelection().getRangeAt(0);
          r.deleteContents();
          var f = document.createDocumentFragment();
          var d = document.createElement("div");
          d.innerHTML = html;
          while (d.firstChild) f.appendChild(d.firstChild);
          r.insertNode(f);
        } else {
          reBody.innerHTML += html;
        }
      }

      /* ---- 键盘快捷键 Ctrl+B / Ctrl+I ---- */
      reBody.addEventListener("keydown", function (e) {
        if (e.ctrlKey || e.metaKey) {
          if (e.key === "b" || e.key === "B") { e.preventDefault(); document.execCommand("bold", false, null); }
          if (e.key === "i" || e.key === "I") { e.preventDefault(); document.execCommand("italic", false, null); }
        }
        /* Tab 缩进 */
        if (e.key === "Tab") { e.preventDefault(); document.execCommand("insertText", false, "  "); }
      });

      /* ---- 文本文档上传（.txt / .md）---- */
      var docInput = qs("#docFileInput");
      if (docInput) {
        docInput.addEventListener("change", function () {
          var file = this.files && this.files[0];
          if (!file) return;
          if (file.size > 2 * 1024 * 1024) { toast("文档不能超过 2MB", "warn"); return; }
          var reader = new FileReader();
          reader.onload = function () {
            var text = reader.result || "";
            var html = text
              .replace(/&/g, "&amp;")
              .replace(/</g, "&lt;")
              .replace(/>/g, "&gt;")
              .replace(/\n\n+/g, '</p><p>')
              .replace(/\n/g, '<br>');
            if (isHtmlMode) { reSrc.value += (reSrc.value ? "\n" : "") + text; }
            else { reBody.innerHTML += (reBody.innerHTML ? "<br><br>" : "") + "<p>" + html + "</p>"; }
            toast("✅ 已导入：" + file.name + "（" + (text.length).toLocaleString() + " 字）");
            this.value = "";
          };
          reader.readAsText(file, "UTF-8");
        });
      }

      /* ---- HTML 源码切换 ---- */
      if (reToggle) {
        reToggle.addEventListener("click", function () {
          isHtmlMode = !isHtmlMode;
          if (isHtmlMode) {
            reSrc.value = reBody.innerHTML;
            reBody.style.display = "none";
            reSrc.style.display = "block";
            this.textContent = "✏️ 编辑";
            this.classList.add("active");
          } else {
            reBody.innerHTML = reSrc.value;
            reSrc.style.display = "none";
            reBody.style.display = "block";
            this.textContent = "<> 源码";
            this.classList.remove("active");
          }
        });
      }

      /* ---- Tab 键支持 ---- */
      reBody.addEventListener("keydown", function (e) {
        if (e.key === "Tab") { e.preventDefault(); document.execCommand("insertText", false, "  "); }
      });

      /* ---- 草稿自动保存 + 恢复 ---- */
      (function initDraft() {
        var DEBOUNCE = 2000, timer = 0;
        function saveDraft() {
          var draft = {
            title: qs("#postTitle").value,
            summary: qs("#postSummary").value,
            category: qs("#postCategory").value,
            tags: qs("#postTags").value,
            cover: qs("#postCover").value,
            content: qs("#reBody") ? qs("#reBody").innerHTML : qs("#postContent").value,
            savedAt: Date.now()
          };
          localStorage.setItem("xhc_draft", JSON.stringify(draft));
        }
        function scheduleSave() { if (timer) clearTimeout(timer); timer = setTimeout(saveDraft, DEBOUNCE); }
        /* 监听输入 */
        var fields = qsa("#postTitle, #postSummary, #postCategory, #postTags, #postCover, #postContent, #reBody");
        fields.forEach(function(f) { if (f) f.addEventListener("input", scheduleSave); });

        /* 恢复草稿（仅在新建文章时） */
        if (editId) return; // 编辑模式不恢复草稿
        var draftStr = localStorage.getItem("xhc_draft");
        if (!draftStr) return;
        try {
          var d = JSON.parse(draftStr);
          if (Date.now() - d.savedAt > 7 * 24 * 3600 * 1000) { localStorage.removeItem("xhc_draft"); return; }
          var note = qs("#editorNote");
          if (!note) return;
          var restoreBtn = '<button class="btn btn-primary sm" id="restoreDraft">恢复草稿</button>';
          var discardBtn = '<button class="btn btn-outline sm" id="discardDraft">丢弃</button>';
          var age = Math.round((Date.now() - d.savedAt) / 60000);
          var ageStr = age < 60 ? age + ' 分钟前' : Math.round(age / 60) + ' 小时前';
          note.innerHTML = '<div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:8px;padding:8px 14px;background:#eef6ff;border-radius:10px;font-size:13px;color:#2c3e50;">' +
            '📝 检测到未发布的草稿（' + ageStr + '）' + '<span> ' + restoreBtn + ' ' + discardBtn + '</span></div>';
          qs("#restoreDraft").addEventListener("click", function() {
            qs("#postTitle").value = d.title || "";
            qs("#postSummary").value = d.summary || "";
            qs("#postCategory").value = d.category || "";
            qs("#postTags").value = d.tags || "";
            qs("#postCover").value = d.cover || "";
            var re = qs("#reBody"); var pc = qs("#postContent");
            if (re) re.innerHTML = d.content || "";
            if (pc) pc.value = d.content || "";
            note.innerHTML = '<div class="note">✅ 草稿已恢复，继续编辑或发布。</div>';
            toast("草稿已恢复");
          });
          qs("#discardDraft").addEventListener("click", function() {
            localStorage.removeItem("xhc_draft");
            note.innerHTML = "";
            toast("草稿已丢弃");
          });
        } catch(e) { localStorage.removeItem("xhc_draft"); }
      })();
    })();
  }

  /* ===========================================================
     UI · 我的帖子
     =========================================================== */
  async function renderMyPosts() {
    if (!qs("#myPostsList")) return;
    var user = await Store.getSession();
    if (!user) { qs("#myPostsNote").innerHTML = '<div class="note warn">请先 <a href="javascript:void(0)" id="mLogin">登录</a>。</div>'; qs("#mLogin").addEventListener("click", openAuth); return; }
    var r = await Store.mine();
    var posts = (r.posts || []).slice().sort(function (a, b) {
      if (!!a.pinned !== !!b.pinned) return a.pinned ? -1 : 1;
      return a.created_at < b.created_at ? 1 : -1;
    });
    var box = qs("#myPostsList");
    box.innerHTML = posts.length === 0
      ? '<div class="empty-state"><div class="big">📭</div>你还没有发布文章。<br><a class="btn btn-primary" href="editor.html" style="margin-top:12px;">去写第一篇</a></div>'
      : posts.map(function (p) {
        return '<div class="card mypost' + (p.pinned ? " pinned" : "") + '">' +
          '<div class="mp-body"><h3><a href="article.html?id=' + encodeURIComponent(p.id) + '">' + (p.pinned ? "📌 " : "") + esc(p.title) + "</a></h3>" +
          '<div class="meta"><span class="cat">' + esc(p.category || "未分类") + "</span><span>👁 " + fmt(p.views) + "</span><span>📅 " + dateOf(p) + "</span></div></div>" +
          '<div class="mp-actions">' +
          '<a class="btn btn-outline sm" href="editor.html?id=' + encodeURIComponent(p.id) + '">编辑</a>' +
          '<button class="btn btn-outline sm pin-btn" data-pin="' + esc(p.id) + '" data-state="' + (p.pinned ? "1" : "0") + '">' + (p.pinned ? "📌 取消置顶" : "📌 置顶") + "</button>" +
          '<button class="btn btn-danger sm" data-del="' + esc(p.id) + '">删除</button>' +
          "</div></div>";
      }).join("");
    qsa("[data-del]", box).forEach(function (b) {
      b.addEventListener("click", function () {
        if (!confirm("确定删除这篇文章？此操作不可恢复。")) return;
        Store.remove(b.dataset.del).then(function () { renderMyPosts(); renderSidebar(); });
      });
    });
    qsa("[data-pin]", box).forEach(function (b) {
      b.addEventListener("click", function () {
        requireAdminThen(function () {
          var id = b.dataset.pin, val = b.dataset.state !== "1";
          Store.pin(id, val).then(function (res) {
            if (res && res.error) { toast("置顶失败：" + (res.error.message || "错误"), "warn"); return; }
            toast(val ? "已置顶 ✓" : "已取消置顶");
            renderMyPosts();
          });
        });
      });
    });
    renderSidebar();
  }

  /* ===========================================================
     UI · 我的收藏
     =========================================================== */
  async function renderFavs() {
    if (!qs("#myFavsList")) return;
    var user = await Store.getSession();
    if (!user) {
      qs("#myFavsNote").innerHTML = '<div class="note warn">请先 <a href="javascript:void(0)" id="fLogin">登录</a> 后查看收藏。</div>';
      qs("#fLogin").addEventListener("click", openAuth);
      return;
    }
    var box = qs("#myFavsList");
    box.innerHTML = '<div class="empty-state"><div class="big">⏳</div>加载收藏中…</div>';
    var r = await Store.listFavorites();
    if (r.error) {
      box.innerHTML = '<div class="empty-state"><div class="big">⚠️</div>加载失败：' + ((r.error && r.error.message) || "网络或数据库错误") + '<br><small>请确认已执行 likes_favorites.sql</small></div>';
      return;
    }
    var posts = r.posts || [];
    box.innerHTML = posts.length === 0
      ? '<div class="empty-state"><div class="big">⭐</div>你还没有收藏任何文章。<br><a class="btn btn-primary" href="index.html" style="margin-top:12px;">去浏览文章</a></div>'
      : posts.map(function (p) { return postCard(p, null); }).join("");
    bindReactions(box);
    renderSidebar();
  }

  /* ===========================================================
     UI · 设置
     =========================================================== */
  async function renderSettings() {
    if (!qs("#settingsForm")) return;
    var user = await Store.getSession();
    if (!user) { qs("#settingsNote").innerHTML = '<div class="note warn">请先 <a href="javascript:void(0)" id="sLogin">登录</a>。</div>'; qs("#sLogin").addEventListener("click", openAuth); return; }
    var prof = await Store.getProfile(user.id);
    var cur = prof || user;
    qs("#avatarPreview").src = cur.avatar_url || SITE.avatar || "assets/images/xhc-96x96.png";
    qs("#setUsername").value = cur.username || "";
    qs("#setDisplayName").value = cur.display_name || user.display_name || "";
    qs("#setBio").value = cur.bio || "";
    var pendingAvatarUrl = null; // 记录新上传的头像 URL（REAL 模式是公网 URL）

    /* 动效开关：回显当前偏好并绑定切换 */
    var mt = qs("#motionToggle");
    if (mt) {
      mt.checked = localStorage.getItem("xhc_motion") !== "off";
      mt.addEventListener("change", function () {
        toggleMotion(!mt.checked);
        toast(mt.checked ? "已开启动效" : "已关闭动效");
      });
    }

    qs("#avatarInput").addEventListener("change", function (e) {
      var f = e.target.files[0]; if (!f) return;
      if (f.size > 2 * 1024 * 1024) { toast("头像过大（≤2MB）", "warn"); return; }
      Store.uploadAvatar(user.id, f).then(function (res) {
        if (res.error) { toast("上传失败：" + res.error.message, "warn"); return; }
        pendingAvatarUrl = res.data.url;
        qs("#avatarPreview").src = res.data.url;
        toast("头像已上传，记得点保存");
      });
    });

    qs("#settingsForm").addEventListener("submit", function (e) {
      e.preventDefault();
      var data = {
        username: qs("#setUsername").value.trim(),
        display_name: qs("#setDisplayName").value.trim(),
        bio: qs("#setBio").value.trim(),
        avatar_url: pendingAvatarUrl || cur.avatar_url || ""
      };
      var pwd = qs("#setPwd").value;
      var btn = qs("#saveSettings"); btn.disabled = true;
      Store.updateProfile(user.id, data).then(function (res) {
        if (res.error) { toast(res.error.message || "保存失败", "warn"); btn.disabled = false; return; }
        if (REAL && pwd) {
          sb.auth.updateUser({ password: pwd }).then(function (pr) {
            btn.disabled = false;
            if (pr.error) toast("资料已保存，密码修改失败：" + pr.error.message, "warn");
            else { toast("设置已保存"); qs("#setPwd").value = ""; }
          });
        } else {
          btn.disabled = false;
          toast(pwd && !REAL ? "演示模式不支持改密码，仅保存资料" : "设置已保存");
          qs("#setPwd").value = "";
        }
      });
    });

    /* 换邮箱：向新邮箱发送确认链接，用户点链接后才完成切换 */
    var ceBtn = qs("#changeEmailBtn");
    if (ceBtn) ceBtn.addEventListener("click", function () {
      if (!REAL) { toast("演示模式不支持换邮箱", "warn"); return; }
      var ne = qs("#setNewEmail").value.trim();
      if (!ne) { toast("请输入新邮箱", "warn"); return; }
      if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(ne)) { toast("邮箱格式不对", "warn"); return; }
      ceBtn.disabled = true; var oldText = ceBtn.textContent; ceBtn.textContent = "发送中…";
      sb.auth.updateUser({ email: ne }).then(function (r) {
        ceBtn.disabled = false; ceBtn.textContent = oldText;
        if (r.error) {
          var msg = (r.error.message || "") + "";
          if (msg.indexOf("redirect_to") >= 0) msg = "请在 Supabase → Authentication → URL Configuration 的 Redirect URLs 里加入当前域名";
          toast("换邮箱失败：" + msg, "warn"); return;
        }
        toast("已向 " + ne + " 发送确认链接，请点链接完成更换");
        qs("#setNewEmail").value = "";
      }).catch(function (e) {
        ceBtn.disabled = false; ceBtn.textContent = oldText;
        toast("换邮箱失败：" + (e && e.message || ""), "warn");
      });
    });

    qs("#deleteAccountBtn").addEventListener("click", function () {
      if (!confirm("警告：注销将永久删除你的资料、文章与评论，且不可恢复。确认？")) return;
      Store.deleteAccount().then(function (res) {
        if (REAL && res.error) { toast("注销失败：" + (res.error.message || "需要管理员权限，请在 Supabase 后台删除用户"), "warn"); return; }
        toast("账号已注销"); setTimeout(function () { location.href = "index.html"; }, 800);
      });
    });
  }

  /* ===========================================================
     UI · 导入示例
     =========================================================== */
  async function renderSeed() {
    if (!qs("#seedBtn")) return;
    var user = await Store.getSession();
    if (!user) { qs("#seedNote").innerHTML = '<div class="note warn">请先 <a href="javascript:void(0)" id="seLogin">登录</a>。</div>'; qs("#seLogin").addEventListener("click", openAuth); return; }
    qs("#seedBtn").addEventListener("click", function () {
      var btn = qs("#seedBtn"); btn.disabled = true; qs("#seedNote").textContent = "导入中…";
      Store.seed(ARTICLES, user.id).then(function (res) {
        btn.disabled = false;
        if (res.error) { qs("#seedNote").textContent = "失败：" + res.error.message; return; }
        qs("#seedNote").textContent = REAL ? (res.skipped ? "示例文章已存在，无需重复导入。" : "成功导入 " + ((res.data || []).length) + " 篇示例文章！") : ("成功导入 " + ((res.data && res.data.added) || 0) + " 篇示例文章！");
        if (!res.skipped) toast("导入完成");
      });
    });
  }

  /* ===========================================================
     UI · 论坛（实时聊天 / 强制登录 / 论坛昵称）
     =========================================================== */
  async function renderForum() {
    var gate = qs("#forumGate"), app = qs("#forumApp");
    if (!gate || !app) return;
    if (!REAL) {
      qs("#forumNote").innerHTML = '<div class="note warn">论坛需要配置 Supabase 后端（config.js 填入 URL 与 anon key）才能多人实时聊天。请先完成配置。</div>';
      return;
    }
    var user = await Store.getSession();
    /* ---- 未登录：强制登录门禁 ---- */
    if (!user) {
      gate.style.display = "block"; app.style.display = "none";
      var lg = qs("#forumLogin");
      if (lg) lg.addEventListener("click", openAuth);
      Store.onChange(function (u) { if (u) location.reload(); });
      return;
    }

    var NICK_KEY = "xhc_forum_nick";
    var nick = (localStorage.getItem(NICK_KEY) || "").trim();

    function showApp() {
      gate.style.display = "none"; app.style.display = "block";
      qs("#nicknameShow").textContent = nick;
      initChat(user);
    }
    function askNick(cb) {
      var modal = qs("#nickModal"), input = qs("#nickInput"),
          err = qs("#nickErr"), save = qs("#nickSave"), cancel = qs("#nickCancel");
      modal.style.display = "flex"; input.value = nick; err.textContent = "";
      input.focus();
      var done = function () {
        var v = input.value.trim();
        if (!v) { err.textContent = "昵称不能为空"; return; }
        nick = v; localStorage.setItem(NICK_KEY, nick);
        modal.style.display = "none"; cb(nick);
      };
      save.onclick = done;
      input.onkeydown = function (e) { if (e.key === "Enter") done(); };
      cancel.onclick = function () { modal.style.display = "none"; if (!nick) location.href = "index.html"; };
    }

    if (!nick) { askNick(showApp); }
    else { showApp(); }

    var cn = qs("#changeNick");
    if (cn) cn.addEventListener("click", function () { askNick(function () { qs("#nicknameShow").textContent = nick; }); });
  }

  function initChat(user) {
    var list = qs("#chatList"), input = qs("#msgInput"), send = qs("#sendBtn");
    var rendered = {};  /* 已渲染消息 id，防实时推送重复 */

    function colorOf(name) {
      var h = 0; for (var i = 0; i < name.length; i++) h = (h * 31 + name.charCodeAt(i)) % 360;
      return "hsl(" + h + ",60%,55%)";
    }
    function timeOf(t) {
      var d = t ? bjDate(t) : new Date();
      if (isNaN(d.getTime())) d = new Date(); /* 非法日期兜底当前时间，避免 NaN:NaN */
      var p = function (x) { return (x < 10 ? "0" : "") + x; };
      return p(d.getHours()) + ":" + p(d.getMinutes());
    }
    function appendMsg(m) {
      if (rendered[m.id]) return; rendered[m.id] = 1;
      /* 兜底：实时推送的新消息可能缺 created_at 或格式非法，给当前时间，避免时间显示 NaN */
      if (!m.created_at || isNaN(bjDate(m.created_at).getTime())) {
        m.created_at = new Date().toISOString();
      }
      var mine = (m.user_id === user.id);
      var el = document.createElement("div");
      el.className = "msg" + (mine ? " mine" : "");
      var initial = (m.nickname || "?").slice(0, 1).toUpperCase();
      el.innerHTML =
        '<div class="msg-ava" style="background:' + colorOf(m.nickname) + '">' + esc(initial) + "</div>" +
        '<div class="msg-body">' +
          '<div class="msg-meta"><span class="msg-name">' + esc(m.nickname) + "</span>" +
          '<span class="msg-time">' + timeOf(m.created_at) + "</span></div>" +
          '<div class="msg-bubble">' + esc(m.content).replace(/\n/g, "<br>") + "</div>" +
        "</div>";
      list.appendChild(el);
      list.scrollTop = list.scrollHeight;
    }

    /* ---- 加载最近 200 条 ---- */
    sb.from("forum_messages").select("*").order("created_at", { ascending: false }).limit(200)
      .then(function (r) {
        if (r.error) { toast("加载消息失败：" + r.error.message, "warn"); return; }
        (r.data || []).reverse().forEach(appendMsg);
      });

    /* ---- 实时订阅新消息 ---- */
    var channel = sb.channel("forum-room")
      .on("postgres_changes", { event: "INSERT", schema: "public", table: "forum_messages" },
        function (payload) {
          appendMsg(payload.new);
          /* 收到他人消息时弹出提示（自己的消息不提示） */
          if (payload.new.user_id !== user.id) notifyNewMessage(payload.new);
        })
      .subscribe();

    /* ---- 新消息提示（桌面通知 + 页面内弹窗）---- */
    function notifyNewMessage(m) {
      var name = m.nickname || "某人";
      var text = (m.content || "").slice(0, 60);
      /* 页面内 toast */
      toast("💬 " + name + "：" + text, "info");
      /* 浏览器桌面通知 */
      if ("Notification" in window) {
        if (Notification.permission === "granted") {
          try { new Notification("[XHC 论坛] 新消息", { body: name + "：" + text }); } catch (e) {}
        }
      }
    }
    /* 进入论坛时请求桌面通知权限 */
    if ("Notification" in window && Notification.permission === "default") {
      Notification.requestPermission().catch(function () {});
    }

    /* ---- 发送 ---- */
    var sending = false;
    async function doSend() {
      var text = input.value.trim();
      if (!text || sending) return;
      /* 禁言检查 */
      if (await checkBanStatus()) { toast("🚫 您已被禁言，无法发送消息", "warn"); return; }
      sending = true; send.disabled = true;
      sb.from("forum_messages").insert({ user_id: user.id, nickname: (localStorage.getItem("xhc_forum_nick") || ""), content: text })
        .then(function (r) {
          sending = false; send.disabled = false;
          if (r.error) { toast("发送失败：" + r.error.message, "warn"); return; }
          input.value = ""; input.focus();
        })
        .catch(function (e) { sending = false; send.disabled = false; toast("发送失败：" + (e && e.message || "网络错误"), "warn"); });
    }
    send.addEventListener("click", doSend);
    input.addEventListener("keydown", function (e) {
      if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); doSend(); }
    });
  }

  /* ===========================================================
     UI · 用户管理（仅管理员）
     =========================================================== */
  async function renderUsers() {
    if (!qs("#userList")) return;
    /* 权限校验：必须是管理员 */
    if (!isAdmin()) {
      /* 未登录管理员则弹窗验证 */
      qs("#userList").innerHTML = '<div class="empty-state"><div class="big">🔒</div>该页面仅限管理员访问。<br><button class="btn btn-primary" id="userAdminLogin" style="margin-top:12px;">输入管理员密码</button></div>';
      qs("#userAdminLogin").addEventListener("click", function () { showAdminLogin(renderUsers); });
      return;
    }

    var box = qs("#userList");
    box.innerHTML = '<div class="empty-state"><div class="big">⏳</div>加载用户列表中…</div>';

    var r;
    try {
      if (REAL) r = await withTimeout(sb.rpc("admin_list_users"), 8000, "读取用户列表");
      else r = { data: JSON.parse(localStorage.getItem("xhc_demo_users") || "[]") };
    } catch (e) {
      var msg = (e && e.message) || "网络或数据库错误";
      var isNet = /超时|Supabase|Failed to fetch|NetworkError|fetch/i.test(msg);
      box.innerHTML = '<div class="empty-state"><div class="big">⚠️</div>加载失败：' + esc(msg) + '<br><small>' +
        (isNet ? "无法连接 Supabase 后端（多半是你的网络无法访问 supabase.co）。请检查网络后点下方重试。" : "请确认已执行 users.sql 且函数无报错") +
        '</small><br><button class="btn btn-primary" id="userRetry" style="margin-top:12px;">重试</button></div>';
      var rb = qs("#userRetry"); if (rb) rb.addEventListener("click", renderUsers);
      return;
    }

    if (!r || r.error) {
      box.innerHTML = '<div class="empty-state"><div class="big">⚠️</div>加载失败：' + ((r && r.error && r.error.message) || "数据库返回空") + '<br><small>请确认已执行 users.sql</small></div>';
      return;
    }
    var users = r.data || [];
    var now = Date.now();
    var onlineCount = 0;

    /* 渲染函数 */
    function render(filter) {
      var list = users.filter(function (u) {
        if (filter === "online") return (new Date(u.last_active).getTime() > now - 5 * 60 * 1000);
        if (filter === "banned") return u.is_banned;
        return true;
      });
      if (filter === "online") onlineCount = list.length;
      qs("#userStats").textContent = "共 " + users.length + " 人 · 在线 " + (function () {
        return users.filter(function (u) { return new Date(u.last_active).getTime() > now - 5 * 60 * 1000; }).length;
      })() + " 人 · 已禁言 " + users.filter(function (u) { return u.is_banned; }).length + " 人";

      if (list.length === 0) { box.innerHTML = '<div class="empty-state"><div class="big">📭</div>暂无符合条件的用户</div>'; return; }

      box.innerHTML = list.map(function (u) {
        var isOnline = new Date(u.last_active).getTime() > now - 5 * 60 * 1000;
        var av = u.avatar_url || SITE.avatar || "assets/images/xhc-96x96.png";
        var nm = u.display_name || u.username || u.email || "未知用户";
        return '<div class="user-row' + (u.is_banned ? " banned" : "") + '" data-uid="' + esc(u.id) + '">' +
          '<div class="u-avatar-wrap"><img class="u-avatar" src="' + esc(av) + '" alt=""><span class="u-online-dot ' + (isOnline ? "on" : "") + '"></span></div>' +
          '<div class="u-info"><div class="u-name">' + esc(nm) + (u.is_banned ? ' <span class="badge-ban">已禁言</span>' : '') + '</div>' +
          '<div class="u-meta">@' + esc(u.username || "—") + ' · ' + esc(u.email || "—") + '</div>' +
          '<div class="u-meta">最后活跃：' + (u.last_active ? dateOf(u) + " " + timeOf(u) : "未知") + '</div></div>' +
          '<div class="u-actions">' +
          '<button class="btn btn-' + (u.is_banned ? "primary" : "warning") + ' sm" data-ban="' + esc(u.id) + '" data-name="' + esc(nm) + '" data-state="' + (u.is_banned ? "1" : "0") + '">' +
          (u.is_banned ? "✅ 解禁" : "🚫 禁言") + '</button>' +
          '</div></div>';
      }).join("");

      qsa("[data-ban]", box).forEach(function (b) {
        b.addEventListener("click", function () {
          adminToggleBan(b.dataset.uid, b.dataset.name, b.dataset.state !== "1");
        });
      });
    }

    qsa("#userTabs a").forEach(function (a) {
      a.addEventListener("click", function () {
        qsa("#userTabs a").forEach(function (x) { x.classList.remove("active"); });
        a.classList.add("active");
        render(a.dataset.filter);
      });
    });

    render("all");
  }

  document.addEventListener("DOMContentLoaded", function () {
    /* ---- 夜间模式：尽早应用，避免闪烁 ---- */
    applyTheme();

    /* ---- OAuth 回跳错误提示（GitHub / 微软登录在 Supabase 侧失败时会带回 error 参数）---- */
    if (OAUTH_ERROR) {
      toast("第三方登录失败：" + OAUTH_ERROR, "warn");
      if (history.replaceState) history.replaceState({}, "", location.pathname);
    }
    /* ---- 动效开关：尽早应用，关闭时即时生效 ---- */
    applyMotion();

    /* ---- 页面加载动画：隐藏 loader ---- */
    (function () {
      var loader = document.getElementById("pageLoader");
      if (loader) loader.classList.remove("active");
    })();

    /* ---- 跳转拦截：点击链接时显示 loading 动画 ---- */
    (function () {
      var loader = document.getElementById("pageLoader");
      if (!loader) return;
      document.addEventListener("click", function (e) {
        var a = e.target.closest("a");
        if (!a) return;
        var href = a.getAttribute("href");
        if (!href || href.indexOf("#") === 0 || href.indexOf("javascript:") === 0) return;
        if (a.target === "_blank") return;
        /* 只拦截同站 .html 链接 */
        if (!/\.html(\?|#|$)/i.test(href) && !/^[\w\-]*\.html$/i.test(href)) return;
        e.preventDefault();
        loader.classList.add("active");
        setTimeout(function () { location.href = href; }, 80);
      });
    })();

    if (!REAL) Store.ensureDemo();
    initHeader();
    renderIndex();
    renderArticle();
    renderEditor();
    renderMyPosts();
    renderFavs();
    renderSettings();
    renderSeed();
    renderForum();
    renderUsers();

    /* 更新最后活跃时间（用于在线状态） */
    (function () {
      if (!REAL) return;
      Store.getSession().then(function (user) {
        if (user) sb.rpc("update_my_last_active");
      });
      /* 每 60 秒刷新一次在线状态 */
      setInterval(function () {
        var p = document.getElementById("userList");
        if (p && isAdmin()) { var u = Store.getSession(); if (u) sb.rpc("update_my_last_active"); }
      }, 60000);
      /* 窗口聚焦时也更新 */
      window.addEventListener("focus", function () {
        var p = document.getElementById("userList");
        if (p && isAdmin()) { var u = Store.getSession(); if (u) sb.rpc("update_my_last_active"); }
      });
    })();
  });
})();
