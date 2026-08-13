/* ===========================================================
   XHC 博客 · Supabase 配置
   -----------------------------------------------------------
   部署真实功能前，请在 Supabase 后台新建项目，然后：
     1) Project Settings → API 复制 Project URL 和 anon public key
     2) 填到下面两个常量
   两个都为空时，站点自动进入「本地演示模式」（文章用 data.js、
      评论存浏览器 localStorage），功能界面照常可点。
   =========================================================== */
window.XHC_CONFIG = {
  SUPABASE_URL: "https://ckitmwadwtoavnigsxag.supabase.co",
  SUPABASE_ANON_KEY: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImNraXRtd2Fkd3RvYXZuaWdzeGFnIiwicm9sZSI6ImFub24iLCJpYXQiOjE3ODU0NzIwNjcsImV4cCI6MjEwMTA0ODA2N30.juUoJi66E7Td5Q-QPA-BUoHa7d4iywwDmaj2B7AIpqY",
  // 是否启用真实后端（URL 与 KEY 都非空时自动开启）
  get enabled() {
    return !!(this.SUPABASE_URL && this.SUPABASE_ANON_KEY);
  }
};
