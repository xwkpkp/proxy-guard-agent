"""core/agent.py — Agent 主循环。

协调 ProxyPool / Rotator / Shield 三者生命周期，提供统计与命令行控制。
"""
from __future__ import annotations

import asyncio
import json
import logging
import time

import aiohttp
from aiohttp import web

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
        self.api_host = a.get("api_host", "127.0.0.1")
        self.api_port = a.get("api_port", 8889)

        self.pool = ProxyPool(
            sources=p["sources"],
            judge_urls=p.get("judge_urls", ["http://httpbin.org/ip"]),
            validate_timeout=p.get("validate_timeout", 8.0),
            validate_concurrency=p.get("validate_concurrency", 60),
            min_size=p.get("min_pool_size", 8),
            max_size=p.get("max_pool_size", 200),
            fetch_proxy=p.get("fetch_proxy", ""),
            dead_cache_path=p.get("dead_cache_path", "dead_cache.db"),
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
        self._api_runner: web.AppRunner | None = None
        self._api_site: web.BaseSite | None = None
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

    # ---- 状态 API ----

    def _build_api(self) -> web.Application:
        app = web.Application()

        async def health(_request: web.Request) -> web.Response:
            return web.json_response({"status": "ok", "ts": time.time()})

        async def stats(_request: web.Request) -> web.Response:
            sh = self.shield.stats
            return web.json_response({
                "pool_size": await self.pool.size(),
                "rotator": self.rotator.metrics(),
                "router": self.router.metrics(),
                "shield": {
                    "requests": sh.requests_total,
                    "blocked": sh.blocked_total,
                    "redline_blocked": sh.redline_blocked,
                    "ssrf_blocked": sh.ssrf_blocked,
                    "injection_detected": sh.injection_detected,
                    "tls_intercepted": sh.tls_intercepted,
                    "by_rule": dict(sorted(sh.by_rule.items(), key=lambda x: -x[1])[:5]),
                },
            })

        async def pool_list(_request: web.Request) -> web.Response:
            proxies = await self.pool.all()
            country = _request.query.get("country", "")
            scheme = _request.query.get("scheme", "")
            limit = int(_request.query.get("limit", "50"))
            rows = []
            for vp in proxies:
                if country and vp.country.upper() != country.upper():
                    continue
                if scheme and vp.scheme != scheme:
                    continue
                rows.append({
                    "endpoint": vp.url,
                    "scheme": vp.scheme,
                    "country": vp.country,
                    "exit_ip": vp.exit_ip,
                    "asn": vp.asn,
                    "latency_ms": vp.latency_ms,
                    "anonymity": vp.anonymity,
                    "streak": vp.streak,
                    "success_count": vp.success_count,
                    "fail_count": vp.fail_count,
                })
            rows.sort(key=lambda x: x["latency_ms"])
            return web.json_response({"count": len(rows), "proxies": rows[:limit]})

        app.router.add_get("/health", health)
        app.router.add_get("/stats", stats)
        app.router.add_get("/pool", pool_list)
        return app

    async def _start_api(self) -> None:
        app = self._build_api()
        self._api_runner = web.AppRunner(app)
        await self._api_runner.setup()
        self._api_site = web.TCPSite(self._api_runner, self.api_host, self.api_port)
        await self._api_site.start()
        log.info("📡 状态API: http://%s:%d/{health,stats,pool}", self.api_host, self.api_port)

    async def start(self) -> None:
        log.info("🚀 Proxy Guard Agent 启动中...")
        await self.pool.start(self.config["pool"]["refresh_interval"])
        await self.rotator.start()
        await self.shield.start()
        await self._start_api()
        self._stat_task = asyncio.create_task(self._print_stats())
        log.info("✅ Agent 就绪。本地代理: %s:%d", self.config["agent"]["listen_host"], self.config["agent"]["listen_port"])
        log.info("   使用方式: HTTP_PROXY=http://127.0.0.1:%d curl http://example.com", self.config["agent"]["listen_port"])

    async def stop(self) -> None:
        self._stopping = True
        if self._stat_task:
            self._stat_task.cancel()
        if self._api_site:
            await self._api_site.stop()
        if self._api_runner:
            await self._api_runner.cleanup()
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