"""core/llm.py — LLM 客户端 + 异步威胁研判队列。

OpenAI 兼容接口（支持 OpenAI / Claude代理 / DeepSeek / 通义 / 任何 /v1/chat/completions 兼容端点）。
检测引擎命中后，样本异步入队，LLM 深判（语义分析），结果写 JSONL。
不阻塞实时流量路径。
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any

import aiohttp

log = logging.getLogger("proxy_guard.llm")

_JUDGE_PROMPT = """你是网络安全分析专家。判断以下 HTTP 请求/响应内容是否恶意。

【上下文】
- 检测引擎已命中规则: {rule_hits}
- 来源: {ctx}
- 目标: {target}

【内容样本（前4KB）】
{sample}

【任务】
判断这段内容的真实意图。规则可能误报，也可能漏报未知攻击。请独立判断。

【输出格式】严格JSON，不要markdown：
{{"verdict": "malicious|suspicious|benign", "attack_type": "具体类型或none", "reason": "50字内理由", "confidence": 0.0到1.0}}"""


@dataclass
class LLMStats:
    queued: int = 0
    analyzed: int = 0
    failed: int = 0
    malicious: int = 0
    suspicious: int = 0
    benign: int = 0
    overrides: int = 0   # 规则命中但LLM判benign（误报纠正）


class LLMClient:
    """OpenAI 兼容 LLM 客户端。"""

    def __init__(
        self,
        base_url: str,
        api_key: str,
        model: str,
        proxy: str = "",
        timeout: float = 30.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.model = model
        self.proxy = proxy
        self.timeout = timeout

    async def chat(self, prompt: str, temperature: float = 0.2, max_tokens: int = 300) -> str:
        """调 /v1/chat/completions，返回文本。"""
        url = f"{self.base_url}/v1/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        kwargs: dict[str, Any] = {}
        if self.proxy:
            kwargs["proxy"] = self.proxy
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    url, json=payload, headers=headers,
                    timeout=aiohttp.ClientTimeout(total=self.timeout), **kwargs,
                ) as resp:
                    if resp.status != 200:
                        body = await resp.text()
                        log.warning("LLM API %d: %s", resp.status, body[:200])
                        return ""
                    data = await resp.json()
                    return data["choices"][0]["message"]["content"].strip()
        except Exception as exc:  # noqa: BLE001
            log.warning("LLM 调用失败: %s", exc)
            return ""

    async def analyze_threat(
        self, sample: str, rule_hits: str, ctx: str, target: str,
    ) -> dict | None:
        """威胁研判。返回 {verdict, attack_type, reason, confidence}。"""
        prompt = _JUDGE_PROMPT.format(
            rule_hits=rule_hits, ctx=ctx, target=target,
            sample=sample[:4096],
        )
        raw = await self.chat(prompt, temperature=0.1, max_tokens=200)
        if not raw:
            return None
        # 提取JSON（容错：LLM可能带```json```或前后文字）
        raw = raw.strip()
        if raw.startswith("```"):
            raw = raw.split("```")[1] if "```" in raw[3:] else raw
        if raw.startswith("json"):
            raw = raw[4:]
        start = raw.find("{")
        end = raw.rfind("}")
        if start >= 0 and end > start:
            raw = raw[start:end + 1]
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            log.debug("LLM 返回非JSON: %s", raw[:100])
            return None


class JudgmentQueue:
    """异步威胁研判队列。shield 命中后 put，后台 worker 消费调 LLM。"""

    def __init__(
        self,
        client: LLMClient | None,
        output_path: str = "llm_judgments.jsonl",
        max_concurrent: int = 2,
    ) -> None:
        self.client = client
        self.output_path = output_path
        self.max_concurrent = max_concurrent
        self._queue: asyncio.Queue = asyncio.Queue(maxsize=500)
        self._workers: list[asyncio.Task] = []
        self.stats = LLMStats()
        self._stopping = False
        self._file_lock = asyncio.Lock()

    async def put(self, sample: str, rule_hits: str, ctx: str, target: str) -> bool:
        """非阻塞入队。队列满则丢弃。"""
        try:
            self._queue.put_nowait((sample, rule_hits, ctx, target, time.time()))
            self.stats.queued += 1
            return True
        except asyncio.QueueFull:
            log.debug("研判队列已满，丢弃样本")
            return False

    async def _worker(self) -> None:
        while not self._stopping:
            try:
                item = await asyncio.wait_for(self._queue.get(), timeout=5.0)
            except asyncio.TimeoutError:
                continue
            sample, rule_hits, ctx, target, ts = item
            if self.client is None:
                continue
            result = await self.client.analyze_threat(sample, rule_hits, ctx, target)
            self.stats.analyzed += 1
            if result is None:
                self.stats.failed += 1
                continue
            verdict = result.get("verdict", "unknown")
            if verdict == "malicious":
                self.stats.malicious += 1
            elif verdict == "suspicious":
                self.stats.suspicious += 1
            elif verdict == "benign":
                self.stats.benign += 1
                self.stats.overrides += 1  # 规则命中但LLM判良性=误报纠正
            await self._write({
                "ts": ts,
                "ctx": ctx,
                "target": target,
                "rule_hits": rule_hits,
                "llm_verdict": verdict,
                "attack_type": result.get("attack_type", ""),
                "reason": result.get("reason", ""),
                "confidence": result.get("confidence", 0),
            })

    async def _write(self, record: dict) -> None:
        async with self._file_lock:
            try:
                with open(self.output_path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(record, ensure_ascii=False) + "\n")
            except Exception as exc:  # noqa: BLE001
                log.debug("研判记录写入失败: %s", exc)

    async def start(self) -> None:
        if self.client is None:
            log.info("LLM 未配置，研判队列空跑")
            return
        for i in range(self.max_concurrent):
            self._workers.append(asyncio.create_task(self._worker()))
        log.info("🧠 LLM 研判队列启动: model=%s, workers=%d, output=%s",
                 self.client.model, self.max_concurrent, self.output_path)

    async def stop(self) -> None:
        self._stopping = True
        for w in self._workers:
            w.cancel()
            try:
                await w
            except asyncio.CancelledError:
                pass

    def metrics(self) -> dict:
        return {
            "queued": self.stats.queued,
            "analyzed": self.stats.analyzed,
            "failed": self.stats.failed,
            "malicious": self.stats.malicious,
            "suspicious": self.stats.suspicious,
            "benign_overrides": self.stats.overrides,
            "queue_size": self._queue.qsize(),
        }