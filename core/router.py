"""core/router.py — 域名路由。

按目标域名决定走直连(DIRECT)还是代理池出口(PROXY)。
默认策略：国内域名直连，海外域名走代理。
所有域名/后缀规则均可在 config.yaml 的 routing 段自定义覆盖。
"""
from __future__ import annotations

import logging
from dataclasses import dataclass

log = logging.getLogger("proxy_guard.router")

DIRECT = "DIRECT"
PROXY = "PROXY"

# ---- 内置国内域名后缀 ----
_DOMESTIC_SUFFIXES = (
    ".cn", ".com.cn", ".gov.cn", ".edu.cn", ".org.cn", ".net.cn",
    ".ac.cn", ".bj.cn", ".sh.cn", ".gd.cn", ".zj.cn", ".js.cn",
    ".tj.cn", ".cq.cn", ".sc.cn", ".sd.cn", ".ha.cn", ".hb.cn",
    ".中国", ".公司", ".网络", ".政务", ".公益", ".网址",
)

# ---- 内置国内常见域名白名单（按母域匹配，子域也命中）----
_DOMESTIC_NAMES = {
    # 搜索 / 门户
    "baidu.com", "sogou.com", "so.com", "sina.com", "sina.com.cn",
    "sohu.com", "163.com", "126.com", "ifeng.com", "qq.com",
    "people.com.cn", "xinhuanet.com", "china.com", "huanqiu.com",
    # 电商
    "taobao.com", "tmall.com", "jd.com", "pinduoduo.com", "suning.com",
    "1688.com", "alibaba.com", "mi.com", "vivo.com.cn", "oppo.com",
    # 支付 / 金融
    "alipay.com", "tenpay.com", "weixin.qq.com", "icbc.com.cn",
    "ccb.com", "boc.cn", "abchina.com", "bank-comm.com", "cmbchina.com",
    # 社交 / 内容
    "weibo.com", "zhihu.com", "douban.com", "bilibili.com",
    "douyin.com", "kuaishou.com", "xiaohongshu.com", "tieba.baidu.com",
    # 视频 / 音乐
    "iqiyi.com", "youku.com", "mgtv.com", "music.163.com",
    "kugou.com", "kuwo.cn", "y.qq.com",
    # 游戏 / 直播
    "douyu.com", "huya.com", "yy.com",
    # 云服务 / 工具
    "cloud.tencent.com", "aliyun.com", "huaweicloud.com",
    "amap.com", "map.baidu.com", "gtimg.com",
    # CDN / 静态资源
    "bdstatic.com", "bdimg.com", "qqcdn.cn", "tencent-cloud.net",
    "alicdn.com", "mmstat.com", "tanx.com", "myqcloud.com",
    # 开发者社区 / 代码托管
    "csdn.net", "cnblogs.com", "jianshu.com", "oschina.net",
    "gitee.com", "coding.net", "segmentfault.com",
    # 快递 / 生活
    "sf-express.com", "yto.net.cn", "sto.cn", "meituan.com",
    "dianping.com", "ele.me", "58.com", "12306.cn",
}


@dataclass
class RouterStats:
    direct: int = 0
    proxy: int = 0
    forced_proxy: int = 0


class DomainRouter:
    """域名路由决策器。

    决策顺序（mode=auto 时）：
      1. 强制代理域名名单 -> PROXY
      2. 命中直连后缀 -> DIRECT
      3. 命中直连白名单 -> DIRECT
      4. 默认 -> PROXY（海外走代理）
    mode=all_direct：全部直连；mode=all_proxy：全部走代理。
    """

    def __init__(self, config: dict) -> None:
        cfg = config.get("routing", {})
        self.mode = cfg.get("mode", "auto")
        # 用户自定义后缀（覆盖内置）
        custom_suf = cfg.get("direct_suffixes", [])
        self.direct_suffixes = tuple(_DOMESTIC_SUFFIXES) + tuple(custom_suf)
        # 用户自定义直连域名（合并到内置白名单）
        custom_direct = cfg.get("direct_domains", []) or []
        self.direct_names = set(_DOMESTIC_NAMES)
        for d in custom_direct:
            self.direct_names.add(d.lower().strip())
        # 用户自定义强制代理域名
        forced_proxy = cfg.get("proxy_domains", []) or []
        self.forced_proxy_names = set(d.lower().strip() for d in forced_proxy)
        self.stats = RouterStats()
        log.info(
            "域名路由就绪 [mode=%s] 直连后缀=%d 直连域名=%d 强制代理域名=%d",
            self.mode, len(self.direct_suffixes), len(self.direct_names), len(self.forced_proxy_names),
        )

    # ---- host 规整 ----
    @staticmethod
    def _normalize(host: str) -> str:
        h = (host or "").lower().strip()
        if h.startswith("["):
            # IPv6 [::1]:443
            idx = h.find("]")
            h = h[1:idx] if idx > 0 else h
        else:
            h = h.split(":")[0]
        return h.strip(".")

    # ---- 名单匹配（含子域）----
    @staticmethod
    def _match_names(host: str, names: set) -> bool:
        if host in names:
            return True
        for n in names:
            if host.endswith("." + n):
                return True
        return False

    # ---- 决策 ----
    def decide(self, host: str) -> str:
        h = self._normalize(host)
        if not h:
            # 拿不到域名，保守走代理
            self.stats.proxy += 1
            return PROXY

        if self.mode == "all_direct":
            self.stats.direct += 1
            return DIRECT
        if self.mode == "all_proxy":
            self.stats.proxy += 1
            return PROXY

        # 1. 强制代理
        if self._match_names(h, self.forced_proxy_names):
            self.stats.forced_proxy += 1
            log.debug("路由 [强制代理] %s", h)
            return PROXY
        # 2. 直连后缀
        for suf in self.direct_suffixes:
            if h.endswith(suf):
                self.stats.direct += 1
                log.debug("路由 [直连 后缀%s] %s", suf, h)
                return DIRECT
        # 3. 直连白名单
        if self._match_names(h, self.direct_names):
            self.stats.direct += 1
            log.debug("路由 [直连 名单] %s", h)
            return DIRECT
        # 4. 默认走代理（海外）
        self.stats.proxy += 1
        log.debug("路由 [代理] %s", h)
        return PROXY

    def metrics(self) -> dict:
        return {
            "mode": self.mode,
            "direct": self.stats.direct,
            "proxy": self.stats.proxy,
            "forced_proxy": self.stats.forced_proxy,
        }