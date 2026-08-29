#!/usr/bin/env python3
"""Fetch WeChat server IPs through an EDNS-aware HTTP DNS endpoint."""

from __future__ import annotations

import gzip
import http.client
import ipaddress
import logging
import os
import re
import ssl
import sys
import xml.etree.ElementTree as ET
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable
from urllib.parse import SplitResult, urlsplit

import dns.edns
import dns.exception
import dns.resolver


GOOGLE_DNS = "8.8.8.8"
DNS_TIMEOUT_SECONDS = 5.0
HTTP_TIMEOUT_SECONDS = 15.0
MAX_RESPONSE_BYTES = 16 * 1024 * 1024
OUTPUT_V4 = Path("wechat-ip-4.txt")
OUTPUT_V6 = Path("wechat-ip-6.txt")
XML_DECLARATION = re.compile(br"^\s*<\?xml[^>]*\?>", re.IGNORECASE)


class ConfigurationError(ValueError):
    """Raised when a required environment setting is invalid."""


class ResponseError(ValueError):
    """Raised when an endpoint response does not match the expected schema."""


@dataclass(frozen=True)
class Endpoint:
    scheme: str
    hostname: str
    port: int
    host_header: str


class DirectHTTPSConnection(http.client.HTTPSConnection):
    """Connect to an IP while validating TLS for a separate DNS hostname."""

    def __init__(
        self,
        connect_ip: str,
        server_hostname: str,
        port: int,
        timeout: float,
    ) -> None:
        super().__init__(
            connect_ip,
            port=port,
            timeout=timeout,
            context=ssl.create_default_context(),
        )
        self._server_hostname = server_hostname

    def connect(self) -> None:
        self.sock = self._create_connection(
            (self.host, self.port), self.timeout, self.source_address
        )
        self.sock = self._context.wrap_socket(
            self.sock, server_hostname=self._server_hostname
        )


def require_environment(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise ConfigurationError(f"Required environment variable {name} is empty")
    return value


def parse_endpoint(raw_value: str) -> Endpoint:
    value = raw_value.strip()
    if not value:
        raise ConfigurationError("HTTP_DNS_DOMAIN is empty")
    if "://" not in value:
        value = f"http://{value}"

    parsed: SplitResult = urlsplit(value)
    if parsed.scheme not in {"http", "https"}:
        raise ConfigurationError("HTTP_DNS_DOMAIN must use HTTP or HTTPS")
    if not parsed.hostname or parsed.username is not None or parsed.password is not None:
        raise ConfigurationError("HTTP_DNS_DOMAIN must contain only a hostname and port")
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise ConfigurationError("Put the request path in HTTP_DNS_PATH")

    try:
        explicit_port = parsed.port
    except ValueError as exc:
        raise ConfigurationError("HTTP_DNS_DOMAIN contains an invalid port") from exc

    hostname = parsed.hostname.rstrip(".")
    if not hostname:
        raise ConfigurationError("HTTP_DNS_DOMAIN contains an invalid hostname")
    try:
        hostname = hostname.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ConfigurationError("HTTP_DNS_DOMAIN contains an invalid hostname") from exc

    port = explicit_port or (443 if parsed.scheme == "https" else 80)
    display_host = f"[{hostname}]" if ":" in hostname else hostname
    host_header = f"{display_host}:{explicit_port}" if explicit_port else display_host
    return Endpoint(parsed.scheme, hostname, port, host_header)


def parse_request_path(raw_value: str) -> str:
    path = raw_value.strip()
    if not path or not path.startswith("/") or path.startswith("//"):
        raise ConfigurationError("HTTP_DNS_PATH must be an absolute HTTP path")
    if "\r" in path or "\n" in path or "#" in path:
        raise ConfigurationError("HTTP_DNS_PATH contains invalid characters")
    return path


def parse_edns_networks(raw_value: str) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for item in raw_value.split(","):
        item = item.strip()
        if not item:
            continue
        try:
            if "/" in item:
                network = ipaddress.ip_network(item, strict=False)
            else:
                address = ipaddress.ip_address(item)
                network = ipaddress.ip_network(
                    f"{address}/{address.max_prefixlen}", strict=False
                )
        except ValueError as exc:
            raise ConfigurationError(f"Invalid EDNS IP or network: {item}") from exc
        if network not in networks:
            networks.append(network)

    if not networks:
        raise ConfigurationError("EDNS_IPS does not contain an IP or network")
    return networks


def resolve_endpoint_ips(
    hostname: str,
    networks: Iterable[ipaddress.IPv4Network | ipaddress.IPv6Network],
) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    """Resolve one endpoint address for every configured EDNS client subnet."""
    resolved: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    seen: set[ipaddress.IPv4Address | ipaddress.IPv6Address] = set()

    for network in networks:
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = [GOOGLE_DNS]
        resolver.timeout = DNS_TIMEOUT_SECONDS
        resolver.lifetime = DNS_TIMEOUT_SECONDS
        resolver.use_edns(
            edns=0,
            payload=1232,
            options=[
                dns.edns.ECSOption(
                    str(network.network_address), network.prefixlen, scopelen=0
                )
            ],
        )

        selected = None
        for record_type in ("A", "AAAA"):
            try:
                answer = resolver.resolve(
                    hostname,
                    record_type,
                    search=False,
                    raise_on_no_answer=False,
                )
                if answer.rrset:
                    selected = ipaddress.ip_address(next(iter(answer)).address)
                    break
            except dns.exception.DNSException as exc:
                logging.warning(
                    "DNS %s lookup failed for EDNS subnet %s: %s",
                    record_type,
                    network,
                    exc,
                )

        if selected is None:
            logging.warning("No endpoint IP found for EDNS subnet %s", network)
        elif selected in seen:
            logging.info("Ignored duplicate endpoint IP %s", selected)
        else:
            seen.add(selected)
            resolved.append(selected)
            logging.info("Resolved endpoint IP %s for EDNS subnet %s", selected, network)

    return resolved


def decompress_response(body: bytes, content_encoding: str) -> bytes:
    encoding = content_encoding.lower().strip()
    try:
        if not encoding or encoding == "identity":
            return body
        if encoding == "gzip":
            return gzip.decompress(body)
        if encoding == "deflate":
            try:
                return zlib.decompress(body)
            except zlib.error:
                return zlib.decompress(body, -zlib.MAX_WBITS)
    except (OSError, EOFError, zlib.error) as exc:
        raise ResponseError(f"Invalid {content_encoding} response body") from exc
    raise ResponseError(f"Unsupported Content-Encoding: {content_encoding}")


def request_endpoint(endpoint: Endpoint, connect_ip: str, path: str) -> bytes:
    if endpoint.scheme == "https":
        connection: http.client.HTTPConnection = DirectHTTPSConnection(
            connect_ip,
            endpoint.hostname,
            endpoint.port,
            HTTP_TIMEOUT_SECONDS,
        )
    else:
        connection = http.client.HTTPConnection(
            connect_ip, endpoint.port, timeout=HTTP_TIMEOUT_SECONDS
        )

    try:
        connection.request(
            "GET",
            path,
            headers={
                "Host": endpoint.host_header,
                "Accept": "application/xml, text/xml;q=0.9, */*;q=0.8",
                "Accept-Encoding": "gzip, deflate",
                "Connection": "close",
                "User-Agent": "get-wechat-ips/1.0",
            },
        )
        response = connection.getresponse()
        body = response.read(MAX_RESPONSE_BYTES + 1)
        if response.status != 200:
            raise ResponseError(f"Unexpected HTTP status {response.status}")
        if len(body) > MAX_RESPONSE_BYTES:
            raise ResponseError("HTTP response is too large")
        return decompress_response(body, response.getheader("Content-Encoding", ""))
    finally:
        connection.close()


def extract_public_ips(
    body: bytes,
) -> set[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    """Extract public IPs from the dns/domainlist portion of a response."""
    if b"<!DOCTYPE" in body.upper():
        raise ResponseError("DOCTYPE is not allowed in the XML response")

    payload = XML_DECLARATION.sub(b"", body, count=1)
    try:
        wrapper = ET.fromstring(b"<response>" + payload + b"</response>")
    except ET.ParseError as exc:
        raise ResponseError(f"Invalid XML response: {exc}") from exc

    dns_element = wrapper.find("dns")
    if dns_element is None:
        raise ResponseError("XML response does not contain a dns element")
    if (dns_element.findtext("retcode") or "").strip() != "0":
        raise ResponseError("XML response retcode is not zero")
    domain_list = dns_element.find("domainlist")
    if domain_list is None:
        raise ResponseError("XML response does not contain domainlist")

    public_ips: set[ipaddress.IPv4Address | ipaddress.IPv6Address] = set()
    for domain in domain_list.findall("domain"):
        if not (domain.get("name") or "").strip():
            raise ResponseError("domainlist contains a domain without a name")
        for ip_element in domain.findall("ip"):
            value = (ip_element.text or "").strip()
            try:
                address = ipaddress.ip_address(value)
            except ValueError as exc:
                raise ResponseError(f"domainlist contains an invalid IP: {value!r}") from exc
            if address.is_global:
                public_ips.add(address)

    return public_ips


def format_addresses(
    addresses: Iterable[ipaddress.IPv4Address | ipaddress.IPv6Address], version: int
) -> str:
    selected = sorted(address for address in addresses if address.version == version)
    suffix = 32 if version == 4 else 128
    return "".join(f"{address}/{suffix}\n" for address in selected)


def write_outputs(
    addresses: set[ipaddress.IPv4Address | ipaddress.IPv6Address],
) -> None:
    contents = {
        OUTPUT_V4: format_addresses(addresses, 4),
        OUTPUT_V6: format_addresses(addresses, 6),
    }
    temporary_files: list[tuple[Path, Path]] = []
    try:
        for destination, content in contents.items():
            temporary = destination.with_name(f".{destination.name}.tmp")
            temporary.write_text(content, encoding="utf-8", newline="\n")
            temporary_files.append((temporary, destination))
        for temporary, destination in temporary_files:
            temporary.replace(destination)
    finally:
        for temporary, _ in temporary_files:
            temporary.unlink(missing_ok=True)


def run() -> None:
    endpoint = parse_endpoint(require_environment("HTTP_DNS_DOMAIN"))
    path = parse_request_path(require_environment("HTTP_DNS_PATH"))
    networks = parse_edns_networks(require_environment("EDNS_IPS"))

    endpoint_ips = resolve_endpoint_ips(endpoint.hostname, networks)
    if not endpoint_ips:
        raise RuntimeError("Google DNS did not return any endpoint IP")

    all_addresses: set[ipaddress.IPv4Address | ipaddress.IPv6Address] = set()
    successful_responses = 0
    for endpoint_ip in endpoint_ips:
        try:
            body = request_endpoint(endpoint, str(endpoint_ip), path)
            addresses = extract_public_ips(body)
        except (OSError, http.client.HTTPException, ssl.SSLError, ResponseError) as exc:
            logging.warning("Request through endpoint IP %s was ignored: %s", endpoint_ip, exc)
            continue
        successful_responses += 1
        all_addresses.update(addresses)
        logging.info(
            "Accepted response through endpoint IP %s with %d public IPs",
            endpoint_ip,
            len(addresses),
        )

    if successful_responses == 0:
        raise RuntimeError("All endpoint requests failed or returned invalid responses")
    if not all_addresses:
        raise RuntimeError("No public IP was found; existing output files were preserved")

    write_outputs(all_addresses)
    ipv4_count = sum(address.version == 4 for address in all_addresses)
    ipv6_count = sum(address.version == 6 for address in all_addresses)
    logging.info("Wrote %d IPv4 and %d IPv6 addresses", ipv4_count, ipv6_count)


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    try:
        run()
    except (ConfigurationError, RuntimeError) as exc:
        logging.error("%s", exc)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
