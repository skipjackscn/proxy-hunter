import asyncio
import unittest
from unittest.mock import patch

from proxyhunter.scanner import RateLimiter, verify_proxy


class BrokenProxyClient:
    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def get(self, *args, **kwargs):
        # Simulates malformed SOCKS5 handshake data from a TCP-open endpoint.
        raise RuntimeError("Malformed reply")


class ProxyVerificationErrorTests(unittest.TestCase):
    def test_malformed_handshake_is_endpoint_failure_not_scan_failure(self):
        async def run():
            with patch("proxyhunter.scanner.httpx.AsyncClient", return_value=BrokenProxyClient()):
                return await verify_proxy(
                    "192.0.2.10",
                    1080,
                    "socks5",
                    {"verify_url": "https://api.ipify.org?format=json"},
                    RateLimiter(100000),
                    asyncio.Semaphore(1),
                )

        result = asyncio.run(run())
        self.assertIsNone(result)


if __name__ == "__main__":
    unittest.main()
