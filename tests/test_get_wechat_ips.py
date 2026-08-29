import ipaddress
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import get_wechat_ips as app


VALID_RESPONSE = b"""<?xml version="1.0" encoding="utf-8"?>
<dns>
  <retcode>0</retcode>
  <domainlist>
    <domain name="one.example">
      <ip>101.226.144.240</ip>
      <ip>127.0.0.1</ip>
      <ip>2001:4860:4860::8888</ip>
    </domain>
    <domain name="two.example"><ip>101.226.144.240</ip></domain>
  </domainlist>
</dns>
<extra><value>allowed sibling root</value></extra>
"""


class ConfigurationTests(unittest.TestCase):
    def test_domain_without_scheme_defaults_to_http_and_supports_port(self):
        endpoint = app.parse_endpoint("dns.example:8080")
        self.assertEqual(endpoint.scheme, "http")
        self.assertEqual(endpoint.hostname, "dns.example")
        self.assertEqual(endpoint.port, 8080)
        self.assertEqual(endpoint.host_header, "dns.example:8080")

    def test_https_requires_explicit_scheme(self):
        endpoint = app.parse_endpoint("https://dns.example")
        self.assertEqual(endpoint.scheme, "https")
        self.assertEqual(endpoint.port, 443)

    def test_edns_ips_accept_hosts_and_cidr_and_remove_duplicates(self):
        networks = app.parse_edns_networks(
            "222.70.19.0/24, 116.21.200.9, 222.70.19.42/24"
        )
        self.assertEqual(
            networks,
            [
                ipaddress.ip_network("222.70.19.0/24"),
                ipaddress.ip_network("116.21.200.9/32"),
            ],
        )


class ResponseTests(unittest.TestCase):
    def test_extracts_only_public_addresses_and_deduplicates(self):
        self.assertEqual(
            app.extract_public_ips(VALID_RESPONSE),
            {
                ipaddress.ip_address("101.226.144.240"),
                ipaddress.ip_address("2001:4860:4860::8888"),
            },
        )

    def test_rejects_nonzero_retcode(self):
        with self.assertRaises(app.ResponseError):
            app.extract_public_ips(
                VALID_RESPONSE.replace(b"<retcode>0</retcode>", b"<retcode>-1</retcode>")
            )

    def test_rejects_invalid_ip_in_otherwise_valid_response(self):
        with self.assertRaises(app.ResponseError):
            app.extract_public_ips(
                VALID_RESPONSE.replace(b"127.0.0.1", b"not-an-ip")
            )

    def test_rejects_invalid_compressed_response(self):
        with self.assertRaises(app.ResponseError):
            app.decompress_response(b"not-deflate", "deflate")

    def test_formatting_is_numeric_sorted_with_prefixes(self):
        addresses = {
            ipaddress.ip_address("10.0.0.1"),
            ipaddress.ip_address("1.1.1.10"),
            ipaddress.ip_address("1.1.1.2"),
        }
        self.assertEqual(
            app.format_addresses(addresses, 4),
            "1.1.1.2/32\n1.1.1.10/32\n10.0.0.1/32\n",
        )

    def test_write_outputs_always_creates_both_files(self):
        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.object(app, "OUTPUT_V4", Path(directory) / "v4.txt"), mock.patch.object(
                app, "OUTPUT_V6", Path(directory) / "v6.txt"
            ):
                app.write_outputs({ipaddress.ip_address("1.1.1.1")})
                self.assertEqual((Path(directory) / "v4.txt").read_text(), "1.1.1.1/32\n")
                self.assertEqual((Path(directory) / "v6.txt").read_text(), "")


class RunTests(unittest.TestCase):
    @mock.patch.dict(
        os.environ,
        {
            "HTTP_DNS_DOMAIN": "dns.example",
            "HTTP_DNS_PATH": "/getdns",
            "EDNS_IPS": "203.0.113.0/24",
        },
        clear=True,
    )
    @mock.patch("get_wechat_ips.write_outputs")
    @mock.patch("get_wechat_ips.request_endpoint", return_value=VALID_RESPONSE)
    @mock.patch(
        "get_wechat_ips.resolve_endpoint_ips",
        return_value=[ipaddress.ip_address("192.0.2.1")],
    )
    def test_run_writes_merged_valid_response(self, _resolve, _request, write):
        app.run()
        written = write.call_args.args[0]
        self.assertIn(ipaddress.ip_address("101.226.144.240"), written)

    @mock.patch.dict(
        os.environ,
        {
            "HTTP_DNS_DOMAIN": "dns.example",
            "HTTP_DNS_PATH": "/getdns",
            "EDNS_IPS": "203.0.113.0/24",
        },
        clear=True,
    )
    @mock.patch("get_wechat_ips.write_outputs")
    @mock.patch("get_wechat_ips.request_endpoint", side_effect=OSError("offline"))
    @mock.patch(
        "get_wechat_ips.resolve_endpoint_ips",
        return_value=[ipaddress.ip_address("192.0.2.1")],
    )
    def test_run_preserves_outputs_when_all_requests_fail(self, _resolve, _request, write):
        with self.assertRaises(RuntimeError):
            app.run()
        write.assert_not_called()


if __name__ == "__main__":
    unittest.main()
