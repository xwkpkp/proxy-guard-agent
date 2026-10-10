"""main.py — Proxy Guard Agent 入口。

用法:
    python main.py                # 用默认 config.yaml 启动
    python main.py -c other.yaml  # 指定配置
    python main.py --test-shield  # 自测检测引擎（不发实际请求）

启动后把浏览器/程序的 HTTP 代理指向 127.0.0.1:8888 即可。
所有流量经公共代理池转发，恶意脚本/流量会被检测并阻断/告警/轮换。
"""
from __future__ import annotations

import argparse
import asyncio
import logging
import os
import sys

import yaml

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.agent import ProxyGuardAgent  # noqa: E402
from core import detectors  # noqa: E402


def setup_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)-7s %(name)s | %(message)s",
        datefmt="%H:%M:%S",
    )


def self_test(rules_dir: str) -> None:
    """离线自测检测引擎，无需网络。"""
    setup_logging("INFO")
    log = logging.getLogger("selftest")
    script_rules, traffic_rules = detectors.load_rules(rules_dir)

    # 响应体样本
    sample_resp = '''
    <html><script>
    eval(function(p,a,c,k,e,d){});
    document.write(unescape("%3Cscript%20src%3D%22http://evil/coinhive.min.js%22%3E"));
    var s = "\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90";
    </script></html>
    '''
    log.info("=== 响应体检测 ===")
    hits = detectors.scan_response(sample_resp, script_rules)
    for h in hits:
        log.info("  命中 [%s] %s (%s)", h.severity, h.rule_id, h.rule_name)
    log.info("响应体命中 %d 条", len(hits))

    # 请求样本
    log.info("=== 请求侧检测 ===")
    req_hits = detectors.scan_request(
        "GET",
        "/.env",
        {"User-Agent": "sqlmap/1.5"},
        "",
        traffic_rules,
    )
    for h in req_hits:
        log.info("  命中 [%s] %s (%s)", h.severity, h.rule_id, h.rule_name)
    log.info("请求侧命中 %d 条", len(req_hits))

    sqli = detectors.scan_request("GET", "/?id=1 UNION SELECT password", {}, "", traffic_rules)
    log.info("SQLi 检测命中 %d 条", len(sqli))

    log.info("自测完成。")


async def amain(config_path: str) -> None:
    with open(config_path, "r", encoding="utf-8") as f:
        config = yaml.safe_load(f)
    setup_logging(config["agent"].get("log_level", "INFO"))
    # 规则目录相对于 config 文件所在
    rules_dir = config["shield"].get("rules_dir", "rules")
    if not os.path.isabs(rules_dir):
        base = os.path.dirname(os.path.abspath(config_path))
        rules_dir = os.path.join(base, rules_dir)
    config["shield"]["rules_dir"] = rules_dir

    agent = ProxyGuardAgent(config)
    try:
        await agent.serve_forever()
    except KeyboardInterrupt:
        await agent.stop()


def main() -> None:
    parser = argparse.ArgumentParser(description="Proxy Guard Agent")
    parser.add_argument("-c", "--config", default=os.path.join(os.path.dirname(__file__), "config.yaml"))
    parser.add_argument("--test-shield", action="store_true", help="离线自测检测引擎")
    parser.add_argument("--rules", default=os.path.join(os.path.dirname(__file__), "rules"))
    args = parser.parse_args()

    if args.test_shield:
        self_test(args.rules)
        return

    try:
        asyncio.run(amain(args.config))
    except KeyboardInterrupt:
        print("\nbye.")


if __name__ == "__main__":
    main()