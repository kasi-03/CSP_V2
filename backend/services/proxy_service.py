"""
Reverse Proxy and Fail-Safe Client IP Resolution Service for Render (SEC-02).

Handles client IP address resolution and protocol detection when CSP_V2
is deployed behind Render's reverse proxy infrastructure.

Architectural & Security Rationale:
1. Render's exact forwarding behavior (whether it strips, overwrites, prepends, or
   appends incoming X-Forwarded-For headers) has NOT been conclusively verified on a live service.
2. Standard Werkzeug ProxyFix(x_for=1) assumes rightmost ordering, which is incompatible
   with Render's documented leftmost client-IP position.
3. Blindly trusting leftmost X-Forwarded-For or True-Client-IP without live verification
   exposes the application to client-side header spoofing.
4. Fail-Safe Resolution Policy:
   - In local development (TRUSTED_PROXIES=0), all forwarded headers are strictly ignored.
     REMOTE_ADDR remains the direct socket peer address (127.0.0.1).
   - In production (TRUSTED_PROXIES > 0), only 'CF-Connecting-IP' is inspected, as Cloudflare
     guarantees overwriting this header at the perimeter edge.
   - 'X-Forwarded-For' and 'True-Client-IP' are deliberately OMITTED as fallbacks until their
     delivery and ordering are conclusively verified against a live Render deployment.
   - If 'CF-Connecting-IP' is missing, malformed, or contains an invalid IP, the client IP is
     marked as 'unknown'. Shared reverse proxy socket IPs (e.g. 10.x.x.x) are NEVER treated
     as genuine visitor IPs, completely preventing proxy-wide account lockouts.
   - X-Forwarded-Host, X-Forwarded-Port, and X-Forwarded-Prefix are never trusted.
   - X-Forwarded-Proto is NOT trusted by default (TRUST_FORWARDED_PROTO=False) because Render's
     exact edge header rewriting has not been verified against a live service. Automatic trust
     is disabled to prevent unencrypted requests from spoofing 'https'. Scheme is only rewritten
     if TRUST_FORWARDED_PROTO is explicitly enabled and validated in production.
"""

import ipaddress
import logging
from typing import Optional

logger = logging.getLogger(__name__)

# Private, loopback, carrier-grade NAT, and link-local address networks
# that must never be treated as verified public client IPs.
_INTERNAL_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),     # Carrier-Grade NAT (RFC 6598)
    ipaddress.ip_network("127.0.0.0/8"),      # IPv4 loopback
    ipaddress.ip_network("169.254.0.0/16"),   # IPv4 link-local
    ipaddress.ip_network("fc00::/7"),         # IPv6 ULA (RFC 4193)
    ipaddress.ip_network("fe80::/10"),        # IPv6 link-local
]


def parse_and_validate_ip(raw: Optional[str]) -> Optional[str]:
    """
    Parse and strictly validate an IPv4 or IPv6 address string.
    Strips whitespace and optional port numbers (e.g. 203.0.113.1:8080 or [2001:db8::1]:443).
    Returns normalized canonical IP string if valid, or None if invalid or malformed.
    """
    if not raw or not isinstance(raw, str):
        return None

    cleaned = raw.strip()
    if not cleaned:
        return None

    # Handle bracketed IPv6 addresses with optional port, e.g. [2001:db8::1]:8443 or [2001:db8::1]
    if cleaned.startswith("["):
        if "]" in cleaned:
            candidate = cleaned[1:cleaned.index("]")]
        else:
            return None
    # Handle IPv4 with port, e.g. 198.51.100.1:8080 (single colon)
    elif ":" in cleaned and cleaned.count(":") == 1:
        candidate = cleaned.split(":", 1)[0].strip()
    else:
        candidate = cleaned

    try:
        ip_obj = ipaddress.ip_address(candidate)
        return str(ip_obj)
    except ValueError:
        return None


def is_verified_client_ip(ip: Optional[str]) -> bool:
    """
    Check if an IP address string is a valid, verified public client IP address.

    Returns False for:
    - None, empty string, or whitespace
    - "unknown"
    - Malformed or invalid IP strings
    - Internal private proxy networks (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10)
    - Loopback addresses (127.0.0.0/8, ::1)
    - Link-local addresses (169.254.0.0/16, fe80::/10)
    - Unspecified addresses (0.0.0.0, ::)

    Returns True for:
    - Routable public IPv4 and IPv6 addresses delivered via verified proxy headers (CF-Connecting-IP).
    """
    if not ip or not isinstance(ip, str):
        return False

    cleaned = ip.strip().lower()
    if not cleaned or cleaned in ("unknown", "none", "null"):
        return False

    try:
        ip_obj = ipaddress.ip_address(cleaned)
    except ValueError:
        return False

    if ip_obj.is_loopback or ip_obj.is_unspecified:
        return False

    for net in _INTERNAL_NETWORKS:
        if ip_obj in net:
            return False

    return True


def extract_render_client_ip(environ: dict) -> Optional[str]:
    """
    Extract and validate the client IP using verified tamper-resistant headers only.

    Policy:
    - Inspect CF-Connecting-IP (overwritten by Cloudflare at the edge).
    - X-Forwarded-For is NOT used as a fallback until live Render behavior is verified.
    - True-Client-IP is NOT used as a fallback.
    - Arbitrary client headers are strictly ignored.
    - If CF-Connecting-IP is missing, empty, or invalid, returns None.
    """
    cf_connecting = environ.get("HTTP_CF_CONNECTING_IP")
    if cf_connecting:
        validated = parse_and_validate_ip(cf_connecting)
        if validated:
            return validated
        logger.warning("Malformed CF-Connecting-IP header received: %r", cf_connecting)

    return None


class RenderProxyMiddleware:
    """
    Fail-safe WSGI middleware for Render reverse proxy environment.

    - When trusted_proxies == 0 (local development): Leaves REMOTE_ADDR and wsgi.url_scheme untouched.
    - When trusted_proxies > 0 (production behind Render):
      - Validates CF-Connecting-IP (the only trusted public client-IP source, subject to verified delivery).
      - If valid, updates environ['REMOTE_ADDR'] with the verified public client IP.
      - If missing or invalid, sets environ['REMOTE_ADDR'] = 'unknown'.
        Does NOT fall back to internal proxy socket address (REMOTE_ADDR).
      - Sets environ['wsgi.url_scheme'] strictly from X-Forwarded-Proto ('https' or 'http')
        ONLY when trust_forwarded_proto is True.
      - When trust_forwarded_proto is False (default): Does NOT trust or inspect X-Forwarded-Proto.
      - Rejects X-Forwarded-Host, X-Forwarded-Port, and X-Forwarded-Prefix.
    """

    def __init__(self, wsgi_app, trusted_proxies: int = 0, trust_forwarded_proto: bool = False):
        self.wsgi_app = wsgi_app
        self.trusted_proxies = max(0, int(trusted_proxies or 0))
        self.trust_forwarded_proto = bool(trust_forwarded_proto)

    def __call__(self, environ, start_response):
        if self.trusted_proxies > 0:
            # 1. Update scheme ONLY if X-Forwarded-Proto is explicitly trusted and verified
            if self.trust_forwarded_proto:
                proto = environ.get("HTTP_X_FORWARDED_PROTO", "").strip().lower()
                if proto in ("https", "http"):
                    environ["wsgi.url_scheme"] = proto

            # 2. Extract and validate client IP from trusted header only
            resolved_ip = extract_render_client_ip(environ)
            if resolved_ip:
                environ["REMOTE_ADDR"] = resolved_ip
            else:
                # Behind Render, if CF-Connecting-IP is missing or invalid,
                # mark client IP as unknown. Do not treat a shared proxy socket IP
                # as a genuine visitor IP.
                environ["REMOTE_ADDR"] = "unknown"

        return self.wsgi_app(environ, start_response)
