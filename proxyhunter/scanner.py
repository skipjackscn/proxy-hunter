from __future__ import annotations

import argparse
import asyncio
import csv
import ipaddress
import json
import logging
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx

ROOT = Path(__file__).resolve().parents[1]
LOG = logging.getLogger("proxyhunter")
DEFAULT_SETTINGS = ROOT / "config/settings.json"
PROTOCOLS = ("socks5", "http", "https")


def load_lines(path: Path) -> list[str]:
    if not path.exists():
        return []
    return [line.strip() for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")]


def load_scope(settings_path: Path) -> tuple[dict[str, Any], list[ipaddress.IPv4Address], list[int]]:
    settings = json.loads(settings_path.read_text(encoding="utf-8"))
    if settings.get("authorized_scope_ack") is not True:
        raise SystemExit("Refusing to scan: set authorized_scope_ack=true after confirming authorization.")
    cidr_path = ROOT / "config/cidrs.txt"
    port_path = ROOT / "config/ports.txt"
    cidrs = load_lines(cidr_path)
    if not cidrs:
        raise SystemExit("No authorized CIDRs configured in config/cidrs.txt; nothing to scan.")

    networks: list[ipaddress.IPv4Network] = []
    for value in cidrs:
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError as exc:
            raise SystemExit(f"Invalid CIDR {value!r}: {exc}")
        if not isinstance(network, ipaddress.IPv4Network):
            raise SystemExit(f"Only IPv4 CIDRs are supported in this version: {value}")
        networks.append(network)

    max_hosts = max(1, min(int(settings.get("max_hosts", 256)), 65536))
    unique: dict[str, ipaddress.IPv4Address] = {}
    for network in networks:
        for ip in network.hosts():
            if ip.is_multicast or ip.is_unspecified or ip.is_loopback or ip.is_link_local:
                continue
            unique[str(ip)] = ip
            if len(unique) > max_hosts:
                raise SystemExit(f"Scope expands beyond max_hosts={max_hosts}. Narrow CIDRs or explicitly raise the cap.")
    if not unique:
        raise SystemExit("The configured CIDRs contain no scannable IPv4 host addresses.")

    ports: list[int] = []
    for value in load_lines(port_path):
        try:
            port = int(value)
        except ValueError:
            raise SystemExit(f"Invalid port: {value}")
        if not 1 <= port <= 65535:
            raise SystemExit(f"Port out of range: {value}")
        if port not in ports:
            ports.append(port)
    if not ports:
        raise SystemExit("No ports configured in config/ports.txt")
    return settings, list(unique.values()), ports


class RateLimiter:
    def __init__(self, rate: float):
        self.interval = 1.0 / max(0.1, rate)
        self.lock = asyncio.Lock()
        self.next_at = 0.0

    async def wait(self) -> None:
        async with self.lock:
            now = time.monotonic()
            delay = max(0.0, self.next_at - now)
            self.next_at = max(now, self.next_at) + self.interval
        if delay:
            await asyncio.sleep(delay)


async def tcp_open(host: str, port: int, timeout: float, limiter: RateLimiter) -> bool:
    await limiter.wait()
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
        writer.close()
        await writer.wait_closed()
        return True
    except (OSError, asyncio.TimeoutError):
        return False


def normalize_verify_url(value: str) -> str:
    parsed = urlsplit(value)
    if parsed.scheme != "https" or not parsed.hostname:
        raise SystemExit("verify_url must be an HTTPS URL")
    return value


async def verify_proxy(host: str, port: int, protocol: str, settings: dict[str, Any],
                       limiter: RateLimiter, semaphore: asyncio.Semaphore) -> dict[str, Any] | None:
    scheme = {"socks5": "socks5h", "http": "http", "https": "https"}[protocol]
    proxy_url = f"{scheme}://{host}:{port}"
    verify_url = normalize_verify_url(str(settings.get("verify_url", "https://api.ipify.org?format=json")))
    timeout = httpx.Timeout(float(settings.get("request_timeout_seconds", 4.0)),
                            connect=float(settings.get("connect_timeout_seconds", 1.5)))
    async with semaphore:
        await limiter.wait()
        started = time.perf_counter()
        try:
            async with httpx.AsyncClient(proxy=proxy_url, timeout=timeout, trust_env=False,
                                         follow_redirects=False, verify=True) as client:
                response = await client.get(verify_url, headers={"User-Agent": "ProxyHunter/2.0"})
                response.raise_for_status()
                body = response.text.strip()
                try:
                    payload = response.json()
                    exit_ip = str(payload.get("ip", "")).strip() if isinstance(payload, dict) else body
                except (ValueError, TypeError):
                    exit_ip = body
                ipaddress.ip_address(exit_ip)
                latency_ms = round((time.perf_counter() - started) * 1000, 2)
                return {
                    "protocol": protocol,
                    "host": host,
                    "port": port,
                    "uri": f"{protocol}://{host}:{port}",
                    "latency_ms": latency_ms,
                    "exit_ip": exit_ip,
                    "status": "alive",
                }
        except Exception as exc:
            # One malformed or incompatible endpoint must never abort the scan.
            LOG.debug("%s://%s:%s failed: %s", protocol, host, port, type(exc).__name__)
            return None


async def run_scan(settings: dict[str, Any], hosts: list[ipaddress.IPv4Address],
                   ports: list[int]) -> list[dict[str, Any]]:
    tcp_concurrency = max(1, min(int(settings.get("tcp_concurrency", 100)), 200))
    verify_concurrency = max(1, min(int(settings.get("verify_concurrency", 100)), 200))
    tcp_rate = max(0.5, min(float(settings.get("tcp_requests_per_second", 40)), 100.0))
    verify_rate = max(0.5, min(float(settings.get("verify_requests_per_second", 40)), 100.0))
    tcp_timeout = max(0.5, min(float(settings.get("connect_timeout_seconds", 1.5)), 10.0))
    queue_size = max(verify_concurrency, min(int(settings.get("queue_size", 1000)), 10000))

    tcp_limiter = RateLimiter(tcp_rate)
    verify_limiter = RateLimiter(verify_rate)
    tcp_queue: asyncio.Queue[tuple[str, int] | None] = asyncio.Queue(
        maxsize=max(tcp_concurrency * 4, 200))
    verify_queues: dict[str, asyncio.Queue[tuple[str, int] | None]] = {
        protocol: asyncio.Queue(maxsize=queue_size) for protocol in PROTOCOLS
    }
    verify_semaphore = asyncio.Semaphore(verify_concurrency)
    results: list[dict[str, Any]] = []
    total_tcp = len(hosts) * len(ports)
    stats: dict[str, Any] = {
        "tcp_done": 0, "tcp_open": 0,
        **{f"{protocol}_done": 0 for protocol in PROTOCOLS},
        **{f"{protocol}_alive": 0 for protocol in PROTOCOLS},
    }

    async def tcp_worker() -> None:
        while True:
            item = await tcp_queue.get()
            try:
                if item is None:
                    return
                host, port = item
                if await tcp_open(host, port, tcp_timeout, tcp_limiter):
                    stats["tcp_open"] += 1
                    # Publish each newly discovered endpoint immediately.
                    for protocol in PROTOCOLS:
                        await verify_queues[protocol].put((host, port))
                stats["tcp_done"] += 1
            finally:
                tcp_queue.task_done()

    async def protocol_worker(protocol: str) -> None:
        queue = verify_queues[protocol]
        while True:
            item = await queue.get()
            try:
                if item is None:
                    return
                host, port = item
                result = await verify_proxy(
                    host, port, protocol, settings, verify_limiter, verify_semaphore)
                stats[f"{protocol}_done"] += 1
                if result is not None:
                    stats[f"{protocol}_alive"] += 1
                    results.append(result)
            finally:
                queue.task_done()

    async def progress_reporter(done_event: asyncio.Event) -> None:
        while not done_event.is_set():
            try:
                await asyncio.wait_for(done_event.wait(), timeout=5.0)
            except asyncio.TimeoutError:
                LOG.info(
                    "PROGRESS TCP %d/%d open=%d | SOCKS5 %d/%d alive=%d | "
                    "HTTP %d/%d alive=%d | HTTPS %d/%d alive=%d | queues tcp=%d "
                    "socks5=%d http=%d https=%d",
                    stats["tcp_done"], total_tcp, stats["tcp_open"],
                    stats["socks5_done"], stats["tcp_open"], stats["socks5_alive"],
                    stats["http_done"], stats["tcp_open"], stats["http_alive"],
                    stats["https_done"], stats["tcp_open"], stats["https_alive"],
                    tcp_queue.qsize(), verify_queues["socks5"].qsize(),
                    verify_queues["http"].qsize(), verify_queues["https"].qsize(),
                )

    LOG.info(
        "Pipeline started: TCP workers=%d rate=%.1f/s; verify workers=%d rate=%.1f/s",
        tcp_concurrency, tcp_rate, verify_concurrency, verify_rate)
    reporter_done = asyncio.Event()
    reporter = asyncio.create_task(progress_reporter(reporter_done))
    tcp_workers = [asyncio.create_task(tcp_worker()) for _ in range(tcp_concurrency)]
    protocol_workers = [
        asyncio.create_task(protocol_worker(protocol))
        for protocol in PROTOCOLS
        for _ in range(verify_concurrency)
    ]

    try:
        for host in hosts:
            for port in ports:
                await tcp_queue.put((str(host), port))
        for _ in tcp_workers:
            await tcp_queue.put(None)
        await tcp_queue.join()
        await asyncio.gather(*tcp_workers)
        LOG.info("TCP phase complete: %d/%d checks; %d open endpoint(s)",
                 stats["tcp_done"], total_tcp, stats["tcp_open"])

        # No more TCP discoveries are possible; let each protocol pool drain.
        for protocol in PROTOCOLS:
            for _ in range(verify_concurrency):
                await verify_queues[protocol].put(None)
        await asyncio.gather(*(queue.join() for queue in verify_queues.values()))
        await asyncio.gather(*protocol_workers)
    finally:
        reporter_done.set()
        await reporter

    results.sort(key=lambda item: item["latency_ms"])
    LOG.info(
        "Verification complete: SOCKS5 %d/%d alive=%d; HTTP %d/%d alive=%d; "
        "HTTPS %d/%d alive=%d",
        stats["socks5_done"], stats["tcp_open"], stats["socks5_alive"],
        stats["http_done"], stats["tcp_open"], stats["http_alive"],
        stats["https_done"], stats["tcp_open"], stats["https_alive"],
    )
    return results


def write_outputs(results: list[dict[str, Any]], settings: dict[str, Any], hosts_count: int,
                  ports_count: int) -> dict[str, Any]:
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    protocols = {name: [r for r in results if r["protocol"] == name] for name in PROTOCOLS}
    summary = {
        "checked_at": now,
        "scope": {"hosts_considered": hosts_count, "ports_configured": ports_count},
        "summary": {
            "total_alive": len(results),
            "socks5": len(protocols["socks5"]),
            "http": len(protocols["http"]),
            "https": len(protocols["https"]),
        },
        "proxies": results,
    }
    data_dir = ROOT / "data/results"
    public_dir = ROOT / "public/data/results"
    output_dir = ROOT / "output"
    for directory in (data_dir, public_dir, output_dir):
        directory.mkdir(parents=True, exist_ok=True)
    serialized = json.dumps(summary, ensure_ascii=False, indent=2) + "\n"
    (data_dir / "latest.json").write_text(serialized, encoding="utf-8")
    (public_dir / "latest.json").write_text(serialized, encoding="utf-8")

    history_path = data_dir / "history.json"
    history = json.loads(history_path.read_text(encoding="utf-8")) if history_path.exists() else []
    history.insert(0, {"checked_at": now, **summary["summary"]})
    history = history[:max(1, int(settings.get("history_limit", 30)))]
    history_text = json.dumps(history, ensure_ascii=False, indent=2) + "\n"
    (data_dir / "history.json").write_text(history_text, encoding="utf-8")
    (public_dir / "history.json").write_text(history_text, encoding="utf-8")

    for protocol, entries in protocols.items():
        (output_dir / f"{protocol}.txt").write_text("".join(r["uri"] + "\n" for r in entries), encoding="utf-8")
    (output_dir / "all-proxies.txt").write_text("".join(r["uri"] + "\n" for r in results), encoding="utf-8")
    for count in (50, 100, 500):
        (output_dir / f"fastest-{count}.txt").write_text(
            "".join(r["uri"] + "\n" for r in results[:count]), encoding="utf-8")
    (output_dir / "proxies.json").write_text(json.dumps(results, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    with (output_dir / "proxies.csv").open("w", newline="", encoding="utf-8-sig") as file:
        writer = csv.DictWriter(file, fieldnames=["protocol", "host", "port", "uri", "latency_ms", "exit_ip", "status"])
        writer.writeheader()
        writer.writerows(results)
    return summary


async def main_async(args: argparse.Namespace) -> None:
    settings, hosts, ports = load_scope(Path(args.config).resolve())
    LOG.info("Authorized scope loaded: %d IPv4 hosts × %d ports", len(hosts), len(ports))
    results = await run_scan(settings, hosts, ports)
    summary = write_outputs(results, settings, len(hosts), len(ports))
    LOG.info("Scan complete: %d live proxy protocol endpoint(s)", summary["summary"]["total_alive"])


def main() -> None:
    parser = argparse.ArgumentParser(description="Verify proxies only inside explicitly authorized CIDR ranges.")
    parser.add_argument("--config", default=str(DEFAULT_SETTINGS))
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")
    asyncio.run(main_async(args))


if __name__ == "__main__":
    main()
