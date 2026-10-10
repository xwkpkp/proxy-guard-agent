"""core/pool.py — 代理池管理。

负责：定期从源抓取候选 -> 验证 -> 维护可用池。
对外提供 acquire()/release()/mark_failed() 接口供 rotator 使用。
"""
from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field

from .sources import ProxyCandidate, fetch_all
from .validator import ValidatedProxy, is_blacklisted, my_ip, validate_batch

log = logging.getLogger("proxy_guard.pool")


@dataclass
class PoolStats:
    total_fetched: int = 0
    total_validated: int = 0
    refresh_count: int = 0
    last_refresh: float = 0.0
    blocked_count: int = 0     # 因检测被阻断的次数


class ProxyPool:
    """线程/协程安全（单事件循环内）的代理池。"""

    def __init__(
        self,
        sources: list[dict],
        judge_urls: list[str],
        validate_timeout: float = 8.0,
        validate_concurrency: int = 60,
        min_size: int = 8,
        max_size: int = 200,
    ) -> None:
        self.sources = sources
        self.judge_urls = judge_urls
        self.validate_timeout = validate_timeout
        self.validate_concurrency = validate_concurrency
        self.min_size = min_size
        self.max_size = max_size

        self._proxies: dict[str, ValidatedProxy] = {}  # key -> proxy
        self._lock = asyncio.Lock()
        self._refresh_task: asyncio.Task | None = None
        self._stopping = False
        self.stats = PoolStats()
        self._my_ip = ""

    # ---- 内部 ----

    async def _do_refresh(self) -> None:
        log.info("开始刷新代理池...")
        cands = await fetch_all(self.sources)
        self.stats.total_fetched += len(cands)
        if not cands:
            log.warning("未抓到任何代理候选，保留现有池")
            return
        # 取本机 IP（用于匿名度判断），失败也不阻塞
        try:
            self._my_ip = await my_ip()
        except Exception:  # noqa: BLE001
            self._my_ip = ""

        validated = await validate_batch(
            cands,
            self.judge_urls,
            timeout=self.validate_timeout,
            concurrency=self.validate_concurrency,
            my_public_ip=self._my_ip,
        )
        self.stats.total_validated += len(validated)
        async with self._lock:
            # 合并：新验证通过的覆盖，保留老的可用代理
            new_map: dict[str, ValidatedProxy] = {}
            for vp in validated[: self.max_size]:
                new_map[vp.key] = vp
            # 老的仍可用的保留（避免刷新瞬间池子变空），跳过黑名单
            for k, vp in self._proxies.items():
                if k not in new_map and vp.fail_count == 0 and not is_blacklisted(k):
                    new_map[k] = vp
            # 也剔除已被拉黑的
            new_map = {k: v for k, v in new_map.items() if not is_blacklisted(k)}
            self._proxies = new_map
            self.stats.refresh_count += 1
            self.stats.last_refresh = time.time()
            log.info("代理池刷新完成，当前可用 %d 个", len(self._proxies))

    async def _refresh_loop(self, interval: float) -> None:
        while not self._stopping:
            try:
                await self._do_refresh()
            except Exception as exc:  # noqa: BLE001
                log.exception("刷新异常: %s", exc)
            try:
                await asyncio.wait_for(asyncio.sleep(interval), timeout=interval)
            except asyncio.TimeoutError:
                pass

    # ---- 公共 ----

    async def start(self, interval: float) -> None:
        # 首次同步刷新一次，确保池子有货再对外服务
        await self._do_refresh()
        self._refresh_task = asyncio.create_task(self._refresh_loop(interval))
        log.info("代理池后台刷新任务已启动，间隔 %.0fs", interval)

    async def stop(self) -> None:
        self._stopping = True
        if self._refresh_task:
            self._refresh_task.cancel()
            try:
                await self._refresh_task
            except asyncio.CancelledError:
                pass

    async def size(self) -> int:
        async with self._lock:
            return len(self._proxies)

    async def all(self) -> list[ValidatedProxy]:
        async with self._lock:
            return list(self._proxies.values())

    async def get(self, key: str) -> ValidatedProxy | None:
        async with self._lock:
            return self._proxies.get(key)

    async def acquire_candidates(self) -> list[ValidatedProxy]:
        """全量快照，供 rotator 自行决策。"""
        return await self.all()

    async def mark_failed(self, key: str) -> None:
        async with self._lock:
            vp = self._proxies.get(key)
            if vp:
                vp.fail_count += 1
                if vp.fail_count >= 3:
                    del self._proxies[key]
                    log.info("剔除失效代理 %s (连续失败 %d)", key, vp.fail_count)

    async def mark_ok(self, key: str) -> None:
        async with self._lock:
            vp = self._proxies.get(key)
            if vp:
                vp.fail_count = 0
                vp.last_ok = time.time()

    async def ensure_min(self) -> None:
        """低于阈值时立刻触发一次刷新。"""
        if await self.size() < self.min_size:
            log.warning("代理池低于阈值 %d，触发即时刷新", self.min_size)
            await self._do_refresh()