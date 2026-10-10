"""core/sources.py — 公共代理源抓取器。

从多个公共代理列表抓取候选代理，统一解析成 ProxyEntry 候选列表。
支持 plain(每行 ip:port) 与 geonode(json) 两种格式，可扩展。
"""
from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import dataclass
from typing import Any

import aiohttp

log = logging.getLogger("proxy_guard.sources")

# ip:port 通用正则
_IPPORT_RE = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3}):(\d{2,5})")


@dataclass
class ProxyCandidate:
    """从代理源抓到的原始候选。"""
    ip: str
    port: int
    scheme: str = "http"   # http / https / socks4 / socks5
    source: str = ""       # 来自哪个源
    country: str = ""
    anonymity: str = ""    # elite / anonymous / transparent（若源提供）

    @property
    def url(self) -> str:
        return f"{self.scheme}://{self.ip}:{self.port}"

    def __hash__(self) -> int:
        return hash((self.ip, self.port, self.scheme))

    def __eq__(self, other: Any) -> bool:
        return (
            isinstance(other, ProxyCandidate)
            and self.ip == other.ip
            and self.port == other.port
            and self.scheme == other.scheme
        )


async def _fetch_text(session: aiohttp.ClientSession, url: str, timeout: float = 20.0) -> str:
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=timeout)) as resp:
            if resp.status != 200:
                log.debug("源 %s 返回非200: %s", url, resp.status)
                return ""
            return await resp.text()
    except Exception as exc:  # noqa: BLE001
        log.debug("抓取源失败 %s: %s", url, exc)
        return ""


def _parse_plain(text: str, source_name: str, scheme: str = "http") -> list[ProxyCandidate]:
    out: list[ProxyCandidate] = []
    for m in _IPPORT_RE.finditer(text):
        ip, port = m.group(1), int(m.group(2))
        if 1 <= port <= 65535:
            out.append(ProxyCandidate(ip=ip, port=port, scheme=scheme, source=source_name))
    return out


def _parse_geonode(text: str, source_name: str) -> list[ProxyCandidate]:
    """geonode 返回 {"data":[{"ip","port","protocols":["http"],...}]}"""
    import json
    try:
        obj = json.loads(text)
    except Exception:  # noqa: BLE001
        return []
    out: list[ProxyCandidate] = []
    for item in obj.get("data", []):
        ip = item.get("ip")
        port = item.get("port")
        if not ip or not port:
            continue
        protocols = item.get("protocols") or ["http"]
        scheme = protocols[0] if isinstance(protocols, list) else str(protocols)
        out.append(ProxyCandidate(
            ip=str(ip),
            port=int(port),
            scheme=scheme.lower(),
            source=source_name,
            country=item.get("country", "") or "",
            anonymity=item.get("anonymityLevel", "") or "",
        ))
    return out


def _scheme_from_url(url: str, name: str) -> str:
    low = url.lower()
    if "socks4" in low or "socks4" in name.lower():
        return "socks4"
    if "socks5" in low or "socks5" in name.lower():
        return "socks5"
    if "https" in low:
        return "https"
    return "http"


async def fetch_all(sources: list[dict]) -> list[ProxyCandidate]:
    """并发抓取所有源，去重后返回候选列表。"""
    seen: set[ProxyCandidate] = set()
    results: list[ProxyCandidate] = []
    headers = {"User-Agent": "Mozilla/5.0 (proxy-guard/0.1)"}
    async with aiohttp.ClientSession(headers=headers) as session:
        tasks = [_fetch_text(session, s["url"]) for s in sources]
        texts = await asyncio.gather(*tasks, return_exceptions=True)
        for src, raw in zip(sources, texts):
            if isinstance(raw, Exception) or not raw:
                continue
            name = src.get("name", src["url"])
            fmt = src.get("format", "plain")
            if fmt == "geonode":
                cands = _parse_geonode(raw, name)
            else:
                scheme = _scheme_from_url(src["url"], name)
                cands = _parse_plain(raw, name, scheme)
            for c in cands:
                if c not in seen:
                    seen.add(c)
                    results.append(c)
            log.info("源 [%s] 抓到 %d 个候选", name, len(cands))
    log.info("合计去重后候选 %d 个", len(results))
    return results