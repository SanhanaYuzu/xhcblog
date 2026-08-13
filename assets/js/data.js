/* ===========================================================
   XHC 博客 · 文章数据
   新增文章：往 ARTICLES 数组里 push 一个对象即可。
   字段说明：
     id        唯一标识（用于 URL ?id= 与评论存储）
     title     标题
     summary   列表页摘要
     category  分类（侧栏会按此聚合）
     tags      标签数组
     date      发布日期 YYYY-MM-DD
     views     浏览量（演示用）
     cover     列表缩略图上的文字/emoji（无图时用）
     content   正文 HTML（支持 h2/h3、p、pre/code、ul、blockquote 等）
   =========================================================== */

const SITE = {
  name: "XHC 的小站",
  domain: "xhc.dpdns.org",
  author: "XHC",
  avatar: "assets/images/xhc-96x96.png",
  bio: "分享 Windows / Linux / MacOS 原版系统与实用软件，全部免费。认准 xhc.dpdns.org 官方域名！",
  links: [
    { label: "主站", url: "http://xhc.dpdns.org" },
    { label: "资源", url: "http://windows.xhc.dpdns.org" },
    { label: "GitHub", url: "https://github.com/SanhanaYuzu/LittleTools-by-Ai" },
    { label: "QQ", url: "tencent://message/?uin=3958588526" }
  ]
};

const ARTICLES = [
  {
    id: "win11-ltsc-2024",
    title: "Windows 11 LTSC 2024 长期服务版下载与安装体验",
    summary: "LTSC 版本去除了应用商店、Cortana、Edge 强制绑定等“累赘”，更适合追求稳定的老用户。本文提供原版镜像获取方式与安装注意事项。",
    category: "系统资源",
    tags: ["Windows", "LTSC", "原版镜像"],
    date: "2026-07-20",
    views: 1820,
    cover: "🪟",
    content: `
      <p>Windows 11 <b>LTSC（Long-Term Servicing Channel）</b> 长期服务版最大的特点就是“安静”：没有频繁的功能推送、没有强制的 Edge 绑定、没有应用商店的弹窗。对于只想安安静静用电脑的人来说，它几乎是 Win10/11 阵营里最省心的选择。</p>

      <h2>一、镜像从哪里来</h2>
      <p>本站只提供 <b>MSDN 原版</b> 镜像，安全有保证。请使用迅雷或 eMule 下载 ED2K / BT 链接，校验哈希后再安装。</p>
      <blockquote>注意：务必核对 SHA1 / SHA256，避免被篡改的第三方镜像植入后门。</blockquote>

      <h2>二、安装前准备</h2>
      <ul>
        <li>一个 ≥8GB 的 U 盘（用 Ventoy 或 Rufus 写入）；</li>
        <li>备份原系统重要数据；</li>
        <li>确认主板已开启 UEFI 与 TPM 2.0（LTSC 2024 仍要求）。</li>
      </ul>

      <h3>制作启动盘（以 Ventoy 为例）</h3>
      <p>把 U 盘格式化为 Ventoy，然后将 ISO 直接拷进去即可，无需反复烧录：</p>
      <pre><code># 假设 U 盘为 /dev/sdb（Linux 下）
ventoy -i /dev/sdb
# 然后把 Win11_LTSC_2024.iso 复制进 U 盘根目录</code><button class="copy">复制</button></pre>

      <h2>三、安装体验</h2>
      <p>整体流程和常规 Win11 一致，但装完桌面非常干净，占用也更低。建议安装后先进入 <code>设置 → 隐私</code> 关闭诊断和广告 ID。</p>

      <h2>四、适合谁</h2>
      <p>老电脑、办公机、家里“只想能用”的长辈机都非常合适。游戏党则建议继续用常规版，兼容性更好。</p>
    `
  },
  {
    id: "ventoy-multiboot",
    title: "Ventoy 一键制作多系统启动盘，装机效率翻倍",
    summary: "一个 U 盘塞下十几个 ISO，开机任选启动。Ventoy 彻底改变了传统“一盘一系统”的装机方式，本文手把手教你。",
    category: "使用教程",
    tags: ["Ventoy", "启动盘", "装机"],
    date: "2026-07-18",
    views: 1340,
    cover: "💾",
    content: `
      <p>传统做启动盘，一个 U 盘只能写一个系统，要换系统就得重新烧录。而 <b>Ventoy</b> 让你把 ISO 文件像普通文件一样丢进 U 盘，开机时直接弹出菜单任选。</p>

      <h2>一、安装 Ventoy 到 U 盘</h2>
      <p>Windows 下打开 Ventoy2Disk.exe，选择 U 盘，点击“安装”即可。注意这会清空 U 盘，请提前备份。</p>
      <pre><code># Linux 命令行安装（谨慎操作，确认设备名）
sudo ventoy -i /dev/sdb</code><button class="copy">复制</button></pre>

      <h2>二、放入 ISO</h2>
      <p>安装完成后，U 盘会出现一个普通分区，直接把各种 ISO 复制进去：</p>
      <ul>
        <li>Win11_LTSC_2024.iso</li>
        <li>LinuxMint.iso</li>
        <li>WePE.iso（维护盘）</li>
      </ul>

      <h2>三、开机启动</h2>
      <p>从 U 盘启动后，Ventoy 会列出所有 ISO，方向键选择、回车即可进入对应安装界面。还支持 <b>Memdisk / Grub2 / 持久化</b> 等高级模式。</p>

      <h3>常见问题</h3>
      <blockquote>部分老主板需要关闭 Secure Boot 才能启动 Ventoy 菜单，开启后个别 ISO 可能报错。</blockquote>
    `
  },
  {
    id: "free-software-2026",
    title: "2026 年站长自用免费软件清单（无广告无捆绑）",
    summary: "盘点一批真正免费、无广告、不弹窗的良心软件，覆盖解压缩、下载、播放、截图等日常场景，全部可在本站“软件资源”频道获取。",
    category: "软件推荐",
    tags: ["软件", "免费", "推荐"],
    date: "2026-07-15",
    views: 2560,
    cover: "🧰",
    content: `
      <p>网上很多“免费软件”其实绑了一堆全家桶。下面这份清单里的每一个，都是站长亲自用过、确认干净的工具。</p>

      <h2>一、下载与解压</h2>
      <ul>
        <li><b>迅雷</b>：ED2K / BT 下载主力（本站提供一键下载）；</li>
        <li><b>7-Zip</b>：开源解压，无广告，支持几乎所有格式；</li>
        <li><b>qBittorrent</b>：纯 BT 客户端，无广告无限速。</li>
      </ul>

      <h2>二、影音与图像</h2>
      <ul>
        <li><b>PotPlayer</b>：解码强、占用低；</li>
        <li><b>ImageGlass</b>：轻量看图，启动飞快。</li>
      </ul>

      <h2>三、系统维护</h2>
      <p>推荐常备一个 <code>WePE</code> 维护盘（用 Ventoy 加载），系统崩了能进 PE 抢救数据。</p>

      <h3>获取方式</h3>
      <p>全部可在本站顶部“资源 → 软件资源”频道跳转下载，网盘请使用对应软件，认准官方域名。</p>
    `
  },
  {
    id: "site-v034",
    title: "XHC 小站 v0.034 Dev 更新公告：新增软件资源频道",
    summary: "本次更新上线了独立的“软件资源”频道，并修复了若干页面问题。感谢 WIN-飞花 提供技术支持与网盘下载链接。",
    category: "网站公告",
    tags: ["公告", "更新"],
    date: "2026-07-12",
    views: 980,
    cover: "📢",
    content: `
      <p>各位访客好，本站已更新至 <b>v0.034 Dev</b>。本次主要变化如下：</p>

      <h2>更新内容</h2>
      <ul>
        <li>新增「软件资源」独立频道，聚合常用免费软件；</li>
        <li>修正页面版本号显示；</li>
        <li>「加入我们」按钮现已正确指向 QQ 群。</li>
      </ul>

      <h2>致谢</h2>
      <blockquote>特别鸣谢：WIN-飞花 提供技术支持与网盘下载链接。</blockquote>

      <h2>联系我们</h2>
      <p>发现任何差错，请拨打站长热线 <code>19901780759</code> 或加站长 QQ <code>3958588526</code> 纠错，感谢支持！</p>
    `
  },
  {
    id: "linux-mint-install",
    title: "Linux Mint 安装教程：给老电脑续命的轻量方案",
    summary: "家里那台跑不动 Win11 的旧机器？Linux Mint 开箱即用、界面友好，是 Windows 用户迁移 Linux 的最佳入门选择。",
    category: "使用教程",
    tags: ["Linux", "Mint", "教程"],
    date: "2026-07-08",
    views: 1120,
    cover: "🐧",
    content: `
      <p>如果你有一台配置不高、又不想被 Win11 硬件要求劝退的电脑，<b>Linux Mint</b> 是平滑过渡的首选：开始菜单、任务栏布局都和 Windows 很像，上手几乎零成本。</p>

      <h2>一、选择版本</h2>
      <ul>
        <li><b>Cinnamon</b>：功能全、观感现代，推荐大多数机器；</li>
        <li><b>MATE / Xfce</b>：更轻量，适合 4GB 内存以下的老机。</li>
      </ul>

      <h2>二、制作启动盘并安装</h2>
      <pre><code># 用 Ventoy 写入后，从 U 盘启动选择“Install Linux Mint”
# 安装类型选“清除整盘并安装”（会清空数据，请备份）</code><button class="copy">复制</button></pre>

      <h2>三、装后必做</h2>
      <ol>
        <li>更换国内软件源以加快更新速度；</li>
        <li>安装显卡与无线网卡驱动（驱动管理器一键搞定）；</li>
        <li>安装常用软件：浏览器、7-Zip、播放器。</li>
      </ol>
      <blockquote>小贴士：Mint 自带“Wine”，可运行部分 Windows 小程序。</blockquote>
    `
  },
  {
    id: "macos-ventura",
    title: "MacOS Ventura 镜像获取与黑苹果避坑指南",
    summary: "想在普通 PC 上体验 MacOS？黑苹果门槛不低。本文梳理镜像来源、EFI 配置与最常见的五类翻车点。",
    category: "系统资源",
    tags: ["MacOS", "黑苹果"],
    date: "2026-07-03",
    views: 1530,
    cover: "🍎",
    content: `
      <p><b>黑苹果（Hackintosh）</b> 指的是在非苹果硬件上安装 MacOS。它能让你以更低成本体验 Mac 生态，但过程比装 Windows 复杂得多。</p>

      <h2>一、镜像来源</h2>
      <p>本站“系统资源 → MacOS”频道提供原版镜像跳转。务必使用原版 <code>.dmg</code> / 恢复版，避免来路不明的“懒人版”。</p>

      <h2>二、硬件建议</h2>
      <ul>
        <li>CPU：Intel 核显（AMD 独显兼容性差）；</li>
        <li>网卡：博通系列兼容性最佳；</li>
        <li>主板：避开过于冷门的型号。</li>
      </ul>

      <h2>三、五大常见翻车点</h2>
      <ol>
        <li>卡 <code>EB</code> / <code>OC</code> 阶段：EFI 配置不匹配；</li>
        <li>声卡无声：需要正确 layout-id；</li>
        <li>睡眠唤醒黑屏：USB 映射没做；</li>
        <li>无法登录 Apple ID：ROM / MLB 未注入；</li>
        <li>升级后进不去：先别急着升大版本。</li>
      </ol>
      <blockquote>提醒：黑苹果仅供学习折腾，生产环境请使用正版 Mac 设备。</blockquote>
    `
  }
];

// 暴露到全局，供 app.js 使用
window.SITE = SITE;
window.ARTICLES = ARTICLES;
