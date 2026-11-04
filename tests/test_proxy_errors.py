import asyncio
import ipaddress
import unittest
from unittest.mock import patch

from proxyhunter.scanner import RateLimiter, run_scan, verify_proxy


class BrokenProxyClient:
    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def get(self, *args, **kwargs):
        raise RuntimeError("Malformed reply")


class ProxyVerificationErrorTests(unittest.TestCase):
    def test_malformed_handshake_is_endpoint_failure_not_scan_failure(self):
        async def run():
            with patch("proxyhunter.scanner.httpx.AsyncClient", return_value=BrokenProxyClient()):
                return await verify_proxy(
                    "192.0.2.10", 1080, "socks5",
                    {"verify_url": "https://api.ipify.org?format=json"},
                    RateLimiter(100000), asyncio.Semaphore(1),
                )
        self.assertIsNone(asyncio.run(run()))


class StalledProxyClient:
    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def get(self, *args, **kwargs):
        await asyncio.Event().wait()


class ProxyVerificationTimeoutTests(unittest.TestCase):
    def test_stalled_socks_handshake_is_killed_by_hard_timeout(self):
        async def run():
            with patch("proxyhunter.scanner.httpx.AsyncClient", return_value=StalledProxyClient()):
                return await verify_proxy(
                    "192.0.2.11", 1080, "socks5",
                    {"verify_url": "https://api.ipify.org?format=json",
                     "verification_hard_timeout_seconds": 0.05},
                    RateLimiter(100000), asyncio.Semaphore(1),
                )
        self.assertIsNone(asyncio.run(run()))


class PipelineTests(unittest.IsolatedAsyncioTestCase):
    async def test_protocol_verification_starts_before_tcp_scan_finishes(self):
        verification_started = asyncio.Event()
        tcp_calls = 0
        checked_protocols = []

        async def fake_tcp_open(host, port, timeout, limiter):
            nonlocal tcp_calls
            tcp_calls += 1
            if tcp_calls == 1:
                return True
            await asyncio.wait_for(verification_started.wait(), timeout=1)
            return False

        async def fake_verify(host, port, protocol, settings, limiter, semaphore):
            checked_protocols.append((host, port, protocol))
            verification_started.set()
            return {
                "protocol": protocol, "host": host, "port": port,
                "uri": f"{protocol}://{host}:{port}", "latency_ms": 1.0,
                "exit_ip": "203.0.113.1", "status": "alive",
            }

        settings = {
            "tcp_concurrency": 1, "verify_concurrency": 2,
            "tcp_requests_per_second": 10000, "verify_requests_per_second": 10000,
            "connect_timeout_seconds": 0.5,
        }
        with patch("proxyhunter.scanner.tcp_open", side_effect=fake_tcp_open), \
             patch("proxyhunter.scanner.verify_proxy", side_effect=fake_verify):
            results = await run_scan(
                settings,
                [ipaddress.ip_address("192.0.2.1"), ipaddress.ip_address("192.0.2.2")],
                [8080],
            )

        self.assertEqual(len(results), 3)
        self.assertEqual({item[2] for item in checked_protocols}, {"socks5", "http", "https"})
        self.assertEqual(tcp_calls, 2)


if __name__ == "__main__":
    unittest.main()
