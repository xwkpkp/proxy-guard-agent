# Proxy Guard Agent

对接公共代理池的防护型本地 HTTP 代理。按域名路由分流、检测恶意脚本与流量、MITM 解密 HTTPS、出口 IP 实时轮换。

> ⚠️ **仅用于低风险、匿名读取、可失败可丢弃的场景。** 公共代理默认不可信，不要用来访问重要账号或传输敏感数据。

## 能力

- **代理池**：多源抓取（proxyscrape/geonode 等）+ 并发验证连通性/延迟/匿名度 + 失效剔除 + 定期刷新
- **IP 轮换**：round_robin / fastest / least_used / random，定时切 + 失败切 + 命中切
- **域名路由**：国内直连，海外走代理池出口（可配置白名单/后缀/强制代理）
- **恶意脚本检测**：13 条签名（packer 混淆 / 挖矿 / shellcode / webshell / PS dropper）+ 启发式（高熵 Base64 / hex）
- **流量检测**：15 条规则（扫描器 UA / 敏感路径 / SQLi / XXE / 命令注入 / CS beacon）
- **SQLi 语义加强**：token 分析，抓 `UnIoN/**/SeLeCt` 等大小写混搭 / 注释分割绕过
- **MITM HTTPS 解密**：自签根 CA + 动态叶子证书签发，解密后过检测引擎
- **安全防护**：数据红线 / SSRF 拦截 / 熔断 / 限速 / 响应注入检测 / 日志脱敏 / CSP 注入
- **代理黑名单**：验证时检测到内容注入即永久拉黑

## 快速开始

```bash
# 安装依赖
pip install -r requirements.txt

# 离线自测检测引擎
python main.py --test-shield

# 启动（监听 127.0.0.1:8888）
python main.py
```

把浏览器/程序 HTTP 代理设为 `127.0.0.1:8888` 即可。

## 配置

复制 `config.example.yaml` 为 `config.yaml`，按需修改。详见文件内注释。

## 目录结构

```
proxy-agent/
├── main.py                 入口
├── config.example.yaml     示例配置
├── requirements.txt
├── core/
│   ├── sources.py          代理源抓取
│   ├── validator.py        代理验证 + 黑名单
│   ├── pool.py             代理池管理
│   ├── rotator.py          出口IP轮换
│   ├── router.py           域名路由
│   ├── detectors.py        检测引擎（签名+启发式）
│   ├── sqli_detect.py      SQLi 语义检测
│   ├── mitm.py             MITM CA + 动态证书
│   ├── safeguards.py       安全防护（红线/SSRF/熔断/脱敏）
│   ├── shield.py           本地HTTP代理防护层
│   └── agent.py            主循环
├── rules/
│   ├── malicious_signatures.yaml
│   └── traffic_rules.yaml
└── tests/
    └── test_sqli_mitm.py
```

## 安全须知

- **cert_store/ 里的 CA 私钥绝不提交**（已 gitignore）。每个使用者应自己生成。
- 公共代理可能记录/篡改/注入流量，本工具做了检测但无法保证绝对安全。
- 不要用公共代理登录重要账号、传密码/Token/支付信息（数据红线会拦截，但别依赖）。
- HTTPS MITM 需信任根 CA，仅在本地测试环境使用。

## License

MIT