"""core/rotator.py — 出口 IP 轮换策略。

维护"当前出口"代理，按策略(round_robin/least_used/fastest/random)选择。
支持：主动定时切换、失败计数自动切换、命中恶意流量强制切换。
"""
from __future__ import annotations

import asyncio
import logging
import random
import time

from .pool import ProxyPool
from .validator import ValidatedProxy

log = logging.getLogger("proxy_guard.rotator")


class Rotator:
    def __init__(
        self,
        pool: ProxyPool,
        strategy: str = "round_robin",
        switch_interval: float = 60.0,
        max_failures: int = 3,
        cooldown: float = 30.0,
    ) -> None:
        self.pool = pool
        self.strategy = strategy
        self.switch_interval = switch_interval
        self.max_failures = max_failures
        self.cooldown = cooldown

        self._current: ValidatedProxy | None = None
        self._rr_index = 0
        self._fail_count = 0
        self._last_switch = time.time()
        self._lock = asyncio.Lock()
        self._switch_task: asyncio.Task | None = None
        self._switches = 0
        self._forced_switches = 0
        self._stopping = False

    # ---- 选择 ----

    def _pick(self, proxies: list[ValidatedProxy]) -> ValidatedProxy | None:
        if not proxies:
            return None
        now = time.time()
        # 过滤冷却中的
        live = [p for p in proxies if (now - p.last_ok) < 600 or p.fail_count == 0]
        if not live:
            live = proxies
        if self.strategy == "fastest":
            return min(live, key=lambda p: p.latency_ms)
        if self.strategy == "least_used":
            return min(live, key=lambda p: p.use_count)
        if self.strategy == "random":
            return random.choice(live)
        # round_robin
        self._rr_index %= len(live)
        pick = live[self._rr_index]
        self._rr_index += 1
        return pick

    async def current(self) -> ValidatedProxy | None:
        async with self._lock:
            return self._current

    async def current_proxy_url(self) -> str | None:
        async with self._lock:
            return self._current.url if self._current else None

    async def _select_new(self) -> ValidatedProxy | None:
        proxies = await self.pool.acquire_candidates()
        # 尽量换一个不同的
        pick = self._pick(proxies)
        if pick and self._current and pick.key == self._current.key and len(proxies) > 1:
            self._rr_index += 1
            pick = self._pick(proxies)
        return pick

    async def switch(self, reason: str = "") -> ValidatedProxy | None:
        """切换出口 IP。返回新的出口代理。"""
        async with self._lock:
            new = await self._select_new()
            if new is None:
                log.warning("切换失败：代理池为空")
                return self._current
            old = self._current.url if self._current else None
            self._current = new
            self._fail_count = 0
            self._last_switch = time.time()
            self._switches += 1
            new.use_count += 1
            tag = f"[{reason}] " if reason else ""
            log.info("%s出口切换：%s -> %s (%.0fms %s)", tag, old, new.url, new.latency_ms, new.anonymity)
            return new

    # ---- 故障 / 强制 ----

    async def report_failure(self) -> ValidatedProxy | None:
        async with self._lock:
            self._fail_count += 1
            if self._current:
                await self.pool.mark_failed(self._current.key)
        if self._fail_count >= self.max_failures:
            log.warning("当前出口连续失败 %d 次，自动切换", self._fail_count)
            return await self.switch("failure")
        return self._current

    async def report_success(self) -> None:
        async with self._lock:
            self._fail_count = 0
            if self._current:
                await self.pool.mark_ok(self._current.key)

    async def force_rotate(self, reason: str = "shield") -> ValidatedProxy | None:
        """命中恶意流量后强制切换出口。"""
        async with self._lock:
            self._forced_switches += 1
        return await self.switch(reason)

    # ---- 主动定时切换 ----

    async def _switch_loop(self) -> None:
        while not self._stopping and self.switch_interval > 0:
            await asyncio.sleep(self.switch_interval)
            if self._stopping:
                break
            try:
                await self.switch("timer")
            except Exception as exc:  # noqa: BLE001
                log.exception("定时切换异常: %s", exc)

    async def start(self) -> None:
        await self.switch("init")
        if self.switch_interval > 0:
            self._switch_task = asyncio.create_task(self._switch_loop())
            log.info("轮换器已启动，主动切换间隔 %.0fs", self.switch_interval)

    async def stop(self) -> None:
        self._stopping = True
        if self._switch_task:
            self._switch_task.cancel()
            try:
                await self._switch_task
            except asyncio.CancelledError:
                pass

    def metrics(self) -> dict:
        return {
            "strategy": self.strategy,
            "switches_total": self._switches,
            "forced_switches": self._forced_switches,
            "current": self._current.url if self._current else None,
            "current_latency_ms": self._current.latency_ms if self._current else None,
        }