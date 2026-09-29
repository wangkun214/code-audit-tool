// 演示模块 —— 刻意包含多处已知漏洞模式，供自检扫描断言使用。
const config = {
  debug: true,
  db_password: "ProdPass#2026",
  privateKey: "-----BEGIN RSA PRIVATE KEY-----",
};

function run(cmd) {
  const { exec } = require("child_process");
  exec("cat " + cmd);
}

function render(userHtml) {
  document.write("<div>" + userHtml + "</div>");
}

async function load(url) {
  const r = await fetch(url);
  return r;
}

function weak(p) {
  return crypto.createHash("md5").update(p).digest("hex");
}

function token() {
  return Math.random().toString(36);
}

module.exports = { run, render, load, weak, token, config };
