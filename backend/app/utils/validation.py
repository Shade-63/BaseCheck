import ipaddress
import socket
from urllib.parse import urlparse
from typing import Tuple


def validate_target(input_val: str) -> Tuple[str, str]:
    """
    Validates and normalizes target input to protect against SSRF and malformed requests.
    
    Returns:
        Tuple[str, str]: (normalized_url, clean_domain)
        
    Raises:
        ValueError: If input is invalid, uses prohibited scheme, or resolves to private/loopback/cloud-metadata IP.
    """
    if not input_val or not isinstance(input_val, str):
        raise ValueError("Target input cannot be empty.")

    raw = input_val.strip()

    # 1. Scheme Check
    if "://" in raw:
        scheme = raw.split("://")[0].lower()
        if scheme not in ("http", "https"):
            raise ValueError(f"Prohibited URL scheme '{scheme}'. Only HTTP and HTTPS are permitted.")
        parsed = urlparse(raw)
    else:
        # Default to https
        parsed = urlparse(f"https://{raw}")

    hostname = parsed.hostname
    if not hostname:
        raise ValueError("Invalid target: Hostname could not be parsed.")

    clean_domain = hostname.lower().strip(".")

    # 2. Block Localhost and Reserved Domain Names
    if clean_domain == "localhost" or clean_domain.endswith((".localhost", ".local", ".internal", ".onion")):
        raise ValueError(f"SSRF Protection: Requests to local/internal domain '{clean_domain}' are blocked.")

    # 3. Direct IP Address Validation
    try:
        ip = ipaddress.ip_address(clean_domain)
        if ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_reserved or ip.is_multicast or ip.is_unspecified:
            raise ValueError(f"SSRF Protection: Requests to private, loopback, or cloud metadata IP '{clean_domain}' are blocked.")
    except ValueError as e:
        # If it's already an SSRF ValueError from above, re-raise it
        if "SSRF Protection" in str(e):
            raise
        # Otherwise clean_domain is a hostname, not a raw IP literal -> proceed to DNS resolution

    # 4. Resolve Domain and Verify Target IP (Prevents DNS Rebinding & SSRF to 127.0.0.1/169.254.169.254)
    try:
        addr_info = socket.getaddrinfo(clean_domain, None)
        for family, _, _, _, sockaddr in addr_info:
            ip_str = sockaddr[0]
            ip = ipaddress.ip_address(ip_str)
            if ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_reserved or ip.is_multicast or ip.is_unspecified:
                raise ValueError(
                    f"SSRF Protection: Domain '{clean_domain}' resolves to prohibited IP ({ip_str})."
                )
    except socket.gaierror:
        raise ValueError(f"DNS Resolution Error: Could not resolve domain '{clean_domain}'.")

    # 5. Build canonical URL
    scheme = parsed.scheme or "https"
    port_str = f":{parsed.port}" if parsed.port and parsed.port not in (80, 443) else ""
    normalized_url = f"{scheme}://{clean_domain}{port_str}"

    return normalized_url, clean_domain
