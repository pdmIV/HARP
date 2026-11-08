"""Bounded public-document reader, executed inside the selected Kali runtime."""
import hashlib
import http.client
from html.parser import HTMLParser
import ipaddress
import json
import socket
import ssl
import sys
import time
from urllib.parse import urlsplit, urljoin


class TextReader(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.hidden = 0
        self.parts = []

    def handle_starttag(self, tag, attrs):
        if tag in {"script", "style", "nav", "footer", "header"}:
            self.hidden += 1
        if not self.hidden and tag in {"p", "div", "br", "pre", "li", "h1", "h2", "h3", "tr"}:
            self.parts.append("\n")

    def handle_endtag(self, tag):
        if tag in {"script", "style", "nav", "footer", "header"} and self.hidden:
            self.hidden -= 1
        if not self.hidden and tag in {"p", "div", "pre", "li", "tr"}:
            self.parts.append("\n")

    def handle_data(self, data):
        if not self.hidden:
            self.parts.append(data)


def public_endpoint(url):
    parsed = urlsplit(url)
    if (parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username or parsed.password
            or parsed.port not in (None, 80 if parsed.scheme == "http" else 443)
            or len(url) > 2000 or any(ord(c) < 33 for c in url)):
        raise ValueError("Only ordinary public HTTP/HTTPS document URLs are supported")
    host = parsed.hostname
    if host.endswith((".htb", ".local", ".internal")) or host == "localhost":
        raise ValueError("Lab and local destinations cannot be research sources")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    addresses = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    if not addresses or any(not ipaddress.ip_address(row[4][0]).is_global or ipaddress.ip_address(row[4][0]).is_multicast for row in addresses):
        raise ValueError("Research sources must resolve exclusively to public addresses")
    return parsed, addresses[0][4][0], port


def fetch(url):
    started = time.monotonic()
    original = url
    for _ in range(4):
        if time.monotonic() - started > 18:
            raise ValueError("Source read time limit exceeded")
        parsed, address, port = public_endpoint(url)
        host = parsed.hostname
        connection = http.client.HTTPSConnection(host, port, timeout=12) if parsed.scheme == "https" else http.client.HTTPConnection(host, port, timeout=12)
        # Pin the validated address. A second DNS lookup must not bypass the check.
        sock = socket.create_connection((address, port), timeout=12)
        if parsed.scheme == "https":
            try:
                sock = ssl.create_default_context().wrap_socket(sock, server_hostname=host)
            except Exception:
                sock.close()
                raise
        connection.sock = sock
        try:
            path = parsed.path or "/"
            if parsed.query:
                path += "?" + parsed.query
            connection.request("GET", path, headers={"User-Agent": "HARP-research/1", "Accept-Encoding": "identity"})
            response = connection.getresponse()
            if response.status in (301, 302, 303, 307, 308):
                location = response.getheader("Location")
                if not location:
                    raise ValueError("Source redirect has no location")
                url = urljoin(url, location)
                continue
            if response.status != 200:
                raise ValueError("Source returned HTTP " + str(response.status))
            mime = response.getheader("Content-Type", "").split(";", 1)[0].lower()
            if mime not in ("text/html", "application/xhtml+xml", "text/plain", "application/json"):
                raise ValueError("Source is not supported HTML, plain text, or JSON")
            if response.getheader("Content-Encoding", "identity").lower() != "identity":
                raise ValueError("Compressed source responses are unsupported")
            chunks, size = [], 0
            while True:
                if time.monotonic() - started > 18:
                    raise ValueError("Source read time limit exceeded")
                connection.sock.settimeout(max(0.1, min(12, 18 - (time.monotonic() - started))))
                chunk = response.read(min(65536, 2_000_001 - size))
                if not chunk:
                    break
                chunks.append(chunk)
                size += len(chunk)
                if size > 2_000_000:
                    raise ValueError("Source exceeds 2 MB read limit")
            data = b"".join(chunks)
            text = data.decode("utf-8", errors="replace")
            if mime in ("text/html", "application/xhtml+xml"):
                reader = TextReader()
                reader.feed(text)
                text = "".join(reader.parts)
            lines = [line.rstrip() for line in text.splitlines() if line.strip()]
            text = "\n".join(lines)
            return {"url": original, "final_url": url, "sha256": hashlib.sha256(data).hexdigest(),
                    "text": text[:80000], "truncated": len(text) > 80000, "bytes": size,
                    "media_type": mime}
        finally:
            connection.close()
    raise ValueError("Source redirect limit exceeded")


if __name__ == "__main__":
    try:
        print(json.dumps(fetch(sys.argv[1]), ensure_ascii=True))
    except Exception as error:
        print(json.dumps({"error": str(error)[:400]}))
        sys.exit(1)
