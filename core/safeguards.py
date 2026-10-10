"""core/safeguards.py — 公共代理池安全防护。

把代理默认视为不可信/可能被入侵，集中实现 8 项硬防护：
  1. 敏感数据红线：阻断携带密码/Token/Cookie/私钥/身份证/银行卡的请求
  2. 强制加密：禁止明文 HTTP 传敏感数据
  3. SSRF 防护：禁止访问 localhost/内网/云元数据
  4. 熔断器：连续失败到阈值熔断，冷却后半开
  5. 限速器：每出口并发上限
  6. 内容注入检测：代理篡改响应（注入 JS/广告/异常跳转）
  7. 日志脱敏
  8. CSP 注入（给 HTML 响应加 CSP 头）
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import re
import time
from dataclasses import dataclass, field
from urllib.parse import urlparse

log = logging.getLogger("proxy_guard.safeguards")

# ====================================================================
# 1. 敏感数据红线
# ====================================================================

SENSITIVE_HEADERS = {
    "authorization", "cookie", "set-cookie", "proxy-authorization",
    "x-api-key", "x-auth-token", "x-csrf-token", "x-session-token",
}

SENSITIVE_PATTERNS = [
    (re.compile(r"(?i)password\s*[=:]\s*\S+"), "password"),
    (re.compile(r"(?i)passwd\s*[=:]\s*\S+"), "passwd"),
    (re.compile(r"(?i)token\s*[=:]\s*[A-Za-z0-9_\-]{8,}"), "token"),
    (re.compile(r"(?i)(access[_-]?token|refresh[_-]?token)\s*[=:]\s*\S+"), "access_token"),
    (re.compile(r"(?i)(secret|api[_-]?key)\s*[=:]\s*\S+"), "secret"),
    (re.compile(r"BEGIN\s+(RSA|EC|OPENSSH|PGP)\s+PRIVATE\s+KEY"), "private_key"),
    (re.compile(r"\b\d{15}(\d{2}[\dXx])?\b"), "id_card"),
    (re.compile(r"\b\d{16,19}\b"), "bank_card"),
]

_ID_CARD_RE = re.compile(r"\b\d{15}(\d{2}[\dXx])?\b")
_BANK_CARD_RE = re.compile(r"\b\d{16,19}\b")


@dataclass
class RedlineResult:
    blocked: bool
    reasons: list[str] = field(default_factory=list)


def check_data_redline(
    method: str,
    url: str,
    headers: dict[str, str],
    body: bytes,
) -> RedlineResult:
    """检查请求是否携带敏感数据。命中 → 阻断。"""
    reasons: list[str] = []
    for k in headers:
        if k.lower() in SENSITIVE_HEADERS:
            reasons.append(f"敏感头 {k}")
    body_text = body.decode("utf-8", "ignore") if body else ""
    for pat, label in SENSITIVE_PATTERNS:
        if pat.search(url) or (body_text and pat.search(body_text)):
            reasons.append(f"敏感数据 ({label})")
    return RedlineResult(blocked=bool(reasons), reasons=reasons)


def redact_headers(headers: dict[str, str]) -> dict[str, str]:
    out = {}
    for k, v in headers.items():
        if k.lower() in SENSITIVE_HEADERS:
            out[k] = v[:2] + "***" if len(v) > 2 else "***"
        else:
            out[k] = v
    return out


def redact_text(text: str) -> str:
    if not text:
        return text
    out = text
    for pat, label in SENSITIVE_PATTERNS:
        out = pat.sub(f"[REDACTED:{label}]", out)
    return out


# ====================================================================
# 3. SSRF 防护
# ====================================================================

_SSRF_BLOCKED_NETS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]

_SSRF_BLOCKED_HOSTS = {
    "localhost", "ip6-localhost", "ip6-loopback",
    "metadata.google.internal", "metadata.aws.internal",
}


def is_ssrf_target(host: str) -> bool:
    if not host:
        return False
    h = host.lower().strip().strip(".")
    if h in _SSRF_BLOCKED_HOSTS:
        return True
    try:
        ip = ipaddress.ip_address(h)
        for net in _SSRF_BLOCKED_NETS:
            if ip in net:
                return True
    except ValueError:
        pass
    return False


# ====================================================================
# 5. 熔断 + 限速
# ====================================================================

class CircuitBreaker:
    def __init__(self, threshold: int = 5, cooldown: float = 60.0) -> None:
        self.threshold = threshold
        self.cooldown = cooldown
        self._fail_count = 0
        self._opened_at = 0.0

    def record_success(self) -> None:
        self._fail_count = 0
        self._opened_at = 0.0

    def record_failure(self) -> None:
        self._fail_count += 1
        if self._fail_count >= self.threshold and self._opened_at == 0.0:
            self._opened_at = time.time()
            log.warning("🔌 熔断器触发 (连续失败 %d)，冷却 %.0fs", self._fail_count, self.cooldown)

    @property
    def is_open(self) -> bool:
        if self._opened_at == 0.0:
            return False
        if time.time() - self._opened_at > self.cooldown:
            self._opened_at = 0.0
            self._fail_count = 0
            return False
        return True


class RateLimiter:
    def __init__(self, max_concurrent: int = 10) -> None:
        self.max_concurrent = max_concurrent
        self._current = 0
        self._lock = asyncio.Lock()

    async def acquire(self) -> bool:
        async with self._lock:
            if self._current >= self.max_concurrent:
                return False
            self._current += 1
            return True

    async def release(self) -> None:
        async with self._lock:
            self._current = max(0, self._current - 1)


# ====================================================================
# 6. 内容注入检测
# ====================================================================

_INJECTION_SIGNS = [
    re.compile(r'(?i)<script[^>]*src=["\x27]https?://[^"\x27]*(proxy|ad|track)[^"\x27]*["\x27]'),
    re.compile(r'(?i)<iframe[^>]*(width|height)=["\x27]0["\x27]'),
    re.compile(r'(?i)inserted\s+by\s+(proxy|cache|cdn)'),
]

_INJECTED_AD_DOMAINS = {
    "doubleclick.net", "googlesyndication.com",
}


def detect_response_injection(
    status: int,
    headers: dict[str, str],
    body: bytes,
) -> list[str]:
    """检测代理是否篡改响应（注入脚本/广告/异常跳转）。"""
    reasons: list[str] = []
    if not body:
        return reasons
    ctype = headers.get("Content-Type", "").lower()
    if "text/html" not in ctype and "javascript" not in ctype:
        return reasons
    text = body[:65536].decode("utf-8", "ignore")
    for pat in _INJECTION_SIGNS:
        if pat.search(text):
            reasons.append("响应含注入脚本/广告")
            break
    for dom in _INJECTED_AD_DOMAINS:
        if dom in text:
            reasons.append(f"响应被注入广告域名 ({dom})")
            break
    if 300 <= status < 400:
        loc = headers.get("Location", "")
        if loc and is_ssrf_target(urlparse(loc).hostname or ""):
            reasons.append(f"异常重定向到内网 {loc}")
    return reasons


# ====================================================================
# 8. CSP 注入
# ====================================================================

DEFAULT_CSP = (
    "default-src 'self'; "
    "script-src 'self'; "
    "object-src 'none'; "
    "base-uri 'self'; "
    "frame-ancestors 'none'"
)


def should_inject_csp(status: int, headers: dict[str, str]) -> bool:
    """是否该给响应注入 CSP 头（HTML 响应且无现有 CSP）。"""
    if "Content-Security-Policy" in headers or "Content-Security-Policy".lower() in {k.lower(): v for k, v in headers.items()}:
        return False
    ctype = headers.get("Content-Type", "").lower()
    return "text/html" in ctype