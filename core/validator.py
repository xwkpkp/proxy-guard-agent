"""core/validator.py — 代理可用性验证。

并发验证候选代理：连通性、延迟、匿名度。
通过则升级为 ValidatedProxy；失败则丢弃。
"""
from __future__ import annotations

import asyncio
import logging
import re
import time
from dataclasses import dataclass, field
from typing import Any

import aiohttp

from .sources import ProxyCandidate

log = logging.getLogger("proxy_guard.validator")

# 用于判断匿名度：judge 站点返回的内容里如果出现本机真实IP则透明，
# 否则匿名。简化：用 httpbin.org/ip 返回的 origin 字段。
_ORIGIN_RE = re.compile(r'"origin"\s*:\s*"([^"]+)"')

# 代理黑名单（检测到注入/篡改的代理永久拉黑）
_BLACKLIST: set[str] = set()


def blacklist(key: str, reason: str = "") -> None:
    """把代理拉黑。"""
    _BLACKLIST.add(key)
    log.warning("🚫 代理拉黑 %s (%s)", key, reason)


def is_blacklisted(key: str) -> bool:
    return key in _BLACKLIST


@dataclass
class ValidatedProxy:
    """通过验证的代理。"""
    ip: str
    port: int
    scheme: str
    source: str
    latency_ms: float          # 验证时实测延迟
    anonymity: str = "unknown" # transparent / anonymous / elite / unknown
    country: str = ""
    last_ok: float = field(default_factory=time.time)
    fail_count: int = 0
    use_count: int = 0
    injection_flag: bool = False   # 验证时检测到内容注入
    blacklisted: bool = False      # 被拉黑

    @property
    def url(self) -> str:
        return f"{self.scheme}://{self.ip}:{self.port}"

    @property
    def key(self) -> str:
        return f"{self.ip}:{self.port}:{self.scheme}"


def _aiohttp_proxy_url(c: ProxyCandidate) -> str:
    """aiohttp 要求的 proxy url 形如 http://ip:port。"""
    return f"{c.scheme}://{c.ip}:{c.port}"


async def _validate_one(
    session: aiohttp.ClientSession,
    cand: ProxyCandidate,
    judge_url: str,
    timeout: float,
    my_public_ip: str = "",
) -> ValidatedProxy | None:
    proxy_url = _aiohttp_proxy_url(cand)
    t0 = time.monotonic()
    try:
        async with session.get(
            judge_url,
            proxy=proxy_url,
            timeout=aiohttp.ClientTimeout(total=timeout),
            allow_redirects=False,
        ) as resp:
            latency = (time.monotonic() - t0) * 1000.0
            if resp.status != 200:
                return None
            body = await resp.text()
    except Exception:  # noqa: BLE001
        return None

    anonymity = "anonymous"
    m = _ORIGIN_RE.search(body)
    if m:
        origin = m.group(1).strip()
        if my_public_ip and origin == my_public_ip:
            anonymity = "transparent"
        else:
            anonymity = "anonymous"
    else:
        anonymity = "elite"

    # ---- 内容注入检测：judge 响应应只有 JSON，不应有 script/iframe ----
    injection_flag = False
    if "<script" in body.lower() or "<iframe" in body.lower():
        injection_flag = True
        log.warning("⚠ 代理 %s 在验证响应中注入脚本，拉黑", proxy_url)
        blacklist(f"{cand.ip}:{cand.port}:{cand.scheme}", "验证响应注入脚本")
        return None

    return ValidatedProxy(
        ip=cand.ip,
        port=cand.port,
        scheme=cand.scheme,
        source=cand.source,
        latency_ms=round(latency, 1),
        anonymity=anonymity,
        country=cand.country,
        injection_flag=injection_flag,
    )


async def validate_batch(
    candidates: list[ProxyCandidate],
    judge_urls: list[str],
    timeout: float = 8.0,
    concurrency: int = 60,
    my_public_ip: str = "",
) -> list[ValidatedProxy]:
    """并发验证一批候选。judge_urls 取第一个可用。"""
    if not candidates:
        return []
    sem = asyncio.Semaphore(concurrency)
    judge = judge_urls[0] if judge_urls else "http://httpbin.org/ip"
    ok: list[ValidatedProxy] = []

    headers = {"User-Agent": "Mozilla/5.0 (proxy-guard/0.1 validator)"}

    async with aiohttp.ClientSession(headers=headers) as session:

        async def _wrapped(cand: ProxyCandidate) -> None:
            async with sem:
                vp = await _validate_one(session, cand, judge, timeout, my_public_ip)
                if vp is not None:
                    ok.append(vp)
                    log.debug("✓ %s  %s  %.0fms  %s", vp.url, vp.anonymity, vp.latency_ms, vp.country)

        await asyncio.gather(*[_wrapped(c) for c in candidates])

    # 按延迟排序
    ok.sort(key=lambda p: p.latency_ms)
    log.info("验证完成：候选 %d，可用 %d", len(candidates), len(ok))
    return ok


async def my_ip(session: aiohttp.ClientSession | None = None) -> str:
    """获取本机出口真实IP，用于匿名度判断。"""
    own = session is None
    if own:
        session = aiohttp.ClientSession()
    try:
        async with session.get("http://httpbin.org/ip", timeout=aiohttp.ClientTimeout(total=10)) as r:  # type: ignore[union-attr]
            body = await r.text()
            m = _ORIGIN_RE.search(body)
            return m.group(1).strip() if m else ""
    except Exception:  # noqa: BLE001
        return ""
    finally:
        if own:
            await session.close()  # type: ignore[union-attr]