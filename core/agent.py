"""core/agent.py — Agent 主循环。

协调 ProxyPool / Rotator / Shield 三者生命周期，提供统计与命令行控制。
"""
from __future__ import annotations

import asyncio
import logging
import time

from .pool import ProxyPool
from .rotator import Rotator
from .router import DomainRouter
from .shield import Shield

log = logging.getLogger("proxy_guard.agent")


class ProxyGuardAgent:
    def __init__(self, config: dict) -> None:
        self.config = config
        a = config["agent"]
        p = config["pool"]
        r = config["rotator"]
        s = config["shield"]

        self.stats_interval = a.get("stats_interval", 30)

        self.pool = ProxyPool(
            sources=p["sources"],
            judge_urls=p.get("judge_urls", ["http://httpbin.org/ip"]),
            validate_timeout=p.get("validate_timeout", 8.0),
            validate_concurrency=p.get("validate_concurrency", 60),
            min_size=p.get("min_pool_size", 8),
            max_size=p.get("max_pool_size", 200),
        )
        self.rotator = Rotator(
            pool=self.pool,
            strategy=r.get("strategy", "round_robin"),
            switch_interval=r.get("switch_interval", 60.0),
            max_failures=r.get("max_failures", 3),
            cooldown=r.get("cooldown", 30.0),
        )
        self.router = DomainRouter(config)
        self.shield = Shield(
            rotator=self.rotator,
            router=self.router,
            listen_host=a["listen_host"],
            listen_port=a["listen_port"],
            scan_request=s.get("scan_request", True),
            scan_response=s.get("scan_response", True),
            block_on_detect=s.get("block_on_detect", True),
            max_body_scan=s.get("max_body_scan", 2 * 1024 * 1024),
            switch_on_detect=s.get("switch_on_detect", True),
            rules_dir=s.get("rules_dir", "rules"),
            mitm_enabled=s.get("mitm_enabled", True),
            cert_store_dir=s.get("cert_store_dir", "cert_store"),
        )
        self._stat_task: asyncio.Task | None = None
        self._stopping = False

    async def _print_stats(self) -> None:
        while not self._stopping:
            await asyncio.sleep(self.stats_interval)
            pool_size = await self.pool.size()
            rot = self.rotator.metrics()
            rt = self.router.metrics()
            sh = self.shield.stats
            log.info(
                "📊 stats | 池=%d 出口=%s %.0fms | 路由 直连=%d 代理=%d | 请求=%d 阻断=%d 检出切换=%d | 红线=%d SSRF=%d 注入=%d | top=%s",
                pool_size, rot.get("current"), rot.get("current_latency_ms") or 0,
                rt["direct"], rt["proxy"],
                sh.requests_total, sh.blocked_total, sh.rotated_on_detect,
                sh.redline_blocked, sh.ssrf_blocked, sh.injection_detected,
                dict(sorted(sh.by_rule.items(), key=lambda x: -x[1])[:3]),
            )

    async def start(self) -> None:
        log.info("🚀 Proxy Guard Agent 启动中...")
        await self.pool.start(self.config["pool"]["refresh_interval"])
        await self.rotator.start()
        await self.shield.start()
        self._stat_task = asyncio.create_task(self._print_stats())
        log.info("✅ Agent 就绪。本地代理: %s:%d", self.config["agent"]["listen_host"], self.config["agent"]["listen_port"])
        log.info("   使用方式: HTTP_PROXY=http://127.0.0.1:%d curl http://example.com", self.config["agent"]["listen_port"])

    async def stop(self) -> None:
        self._stopping = True
        if self._stat_task:
            self._stat_task.cancel()
        await self.shield.stop()
        await self.rotator.stop()
        await self.pool.stop()
        log.info("Agent 已停止")

    async def serve_forever(self) -> None:
        await self.start()
        try:
            while not self._stopping:
                await asyncio.sleep(1)
        except asyncio.CancelledError:
            pass
        finally:
            await self.stop()