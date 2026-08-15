/* ============================================
   关于本站 · 更新日志渲染（独立脚本，不依赖 app.js）
   ============================================ */
(function () {
  function esc(s) {
    return String(s == null ? "" : s).replace(/[&<>"']/g, function (m) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[m];
    });
  }
  var list = document.getElementById("clList");
  if (!list) return;
  var logs = (window.XHC_CHANGELOG || []);
  if (!logs.length) {
    list.innerHTML = '<div class="cl-item" style="color:#8a94a3;">暂无更新日志</div>';
    return;
  }
  list.innerHTML = logs.map(function (g) {
    var head =
      '<div class="cl-head">' +
        '<span class="cl-date">' + esc(g.date || "") + '</span>' +
        (g.version ? '<span class="cl-ver">' + esc(g.version) + '</span>' : '') +
      '</div>';
    var lis = (g.items || [])
      .map(function (it) { return '<li>' + it + '</li>'; })
      .join("");
    return '<div class="cl-item">' + head + '<ul>' + lis + '</ul></div>';
  }).join("");
  var y = document.getElementById("year");
  if (y) y.textContent = new Date().getFullYear();
})();