# XHC 博客

个人博客系统，设计套用 XHC 主站风格（蓝 `#0d6efd` / 圆角卡片），功能参考 CSDN 博客。
**纯静态站点**，无需后端服务器即可运行；要启用「真实账号 / 发帖 / 评论 / 头像」，接一个免费的 [Supabase](https://supabase.com) 后端即可（前端仍是静态，可部署到 GitHub Pages）。

## 功能

- 文章流（最新 / 最热）、分类、标签、搜索、分页
- 文章详情：目录 TOC、代码高亮 + 一键复制、上一篇 / 下一篇
- **真实账号体系**：邮箱注册 / 登录 / 注销
- **个人资料**：改用户名 / 昵称 / 简介、上传头像
- **发帖 / 删帖**：写文章（标题 / 摘要 / 分类 / 标签 / 正文 / 封面），作者可删除
- **评论**：登录后发表，显示头像 + 昵称，作者可删自己的评论
- 双模式：未配置 Supabase 时自动进入「本地演示模式」（数据存浏览器），配置后变真实后端

## 目录结构

```
xhc-blog/
├─ index.html        # 首页（列表 + 侧栏 + 搜索）
├─ article.html      # 文章详情（正文 + 目录 + 评论）
├─ editor.html       # 写文章 / 编辑
├─ myposts.html      # 我的帖子（删除）
├─ settings.html     # 账户设置（头像 / 资料 / 密码 / 注销）
├─ seed.html         # 登录后一键导入示例文章
├─ schema.sql        # Supabase 建表 + RLS 策略（复制到 SQL Editor 执行）
└─ assets/
   ├─ css/style.css
   ├─ js/config.js   # ★ Supabase 配置（填 key 处）
   ├─ js/data.js     # 示例文章 + 站点信息（演示模式数据源）
   ├─ js/app.js      # 全部交互逻辑
   └─ images/xhc-96x96.png
```

## 本地预览

```bash
cd xhc-blog
python3 -m http.server 8080
# 浏览器打开 http://127.0.0.1:8080
```

未配置 Supabase 时即为演示模式：文章来自 `data.js`，注册 / 登录 / 发帖 / 评论数据都存在本浏览器（密码明文，**仅用于体验，不要当真**）。

## 启用真实后端（Supabase）

1. 打开 https://supabase.com 注册并 **New Project**（免费版即可）。
2. 左侧 **SQL Editor → New query**，把本仓库 `schema.sql` 全文粘贴进去执行（建表 + 行级安全 + 头像桶）。
3. **Project Settings → API**，复制：
   - `Project URL`
   - `anon` / `public` key
4. 打开 `assets/js/config.js`，填入：
   ```js
   window.XHC_CONFIG = {
     SUPABASE_URL: "https://xxxx.supabase.co",
     SUPABASE_ANON_KEY: "eyJhbGciOi..."
   };
   ```
   两个都非空后，站点自动切换到真实模式。
5. 注册第一个账号（建议用你自己的邮箱，作为「站长」）。
6. 登录后访问 `seed.html`，点「导入示例文章」把 `data.js` 的示例文章写入 Supabase（以你为作者）。

> 邮箱确认：Supabase 默认开启 "Confirm signup"，注册后会往邮箱发确认链接；点开后再登录。
> 想关掉确认：Auth → Providers → Email → 关闭 "Confirm email"。

## 部署到 GitHub Pages

1. 在 GitHub 新建一个仓库（如 `xhc-blog`）。
2. 把 `xhc-blog/` 目录内容推上去：
   ```bash
   cd xhc-blog
   git init
   git add -A
   git commit -m "XHC blog"
   git branch -M main
   git remote add origin https://github.com/<你的用户名>/xhc-blog.git
   git push -u origin main
   ```
3. 仓库 **Settings → Pages → Build and deployment → Source 选 "Deploy from a branch"**，分支选 `main` / 根目录 `/`。
4. 几分钟生效后访问 `https://<你的用户名>.github.io/xhc-blog/`。

如果在子路径（如 `/xhc-blog/`）下访问，文章内的相对链接（`article.html?id=`、`assets/...`）都能正常工作。

## 注意事项

- **演示模式**账号密码存浏览器、明文，**不要用于真实多用户场景**。
- **注销账号**：演示模式可直接删除；真实模式因 Supabase 安全限制，普通用户无法直接删自己账号，需在 Supabase 后台 **Auth → Users** 手动删除（或后续接 Admin API）。
- 头像存储桶 `avatars` 已设为公开读、登录用户可写；若上传失败，检查 Storage 策略是否随 `schema.sql` 一起执行。
- 主站底部 `mobiri.se` 链接是给服务商的广告位，本博客未包含。
