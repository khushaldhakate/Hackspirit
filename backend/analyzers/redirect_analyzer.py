import ipaddress
import socket
from urllib.parse import urlparse
import httpx

PRIVATE_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]

def is_private_target(hostname: str) -> bool:
    """Blocks SSRF targeting local or private network IP addresses."""
    if not hostname or hostname.lower() in ["localhost", "127.0.0.1", "::1"]:
        return True

    try:
        # Resolve hostname to IP address
        ip_str = socket.gethostbyname(hostname)
        ip_obj = ipaddress.ip_address(ip_str)
        for net in PRIVATE_NETWORKS:
            if ip_obj in net:
                return True
    except Exception:
        pass

    return False

def trace_url_redirects(start_url: str, max_redirects: int = 4, timeout_sec: float = 1.0) -> dict:
    """
    Safely follows HTTP 301/302 redirects up to max_redirects limit.
    Enforces scheme validation and private IP blocking.
    """
    current_url = start_url.strip()
    if not current_url.startswith(("http://", "https://")):
        current_url = "http://" + current_url

    redirect_chain = []
    flags = []
    
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) PhishGuard-Scanner/1.0"
    }

    try:
        with httpx.Client(timeout=timeout_sec, follow_redirects=False, headers=headers) as client:
            for step in range(max_redirects):
                parsed = urlparse(current_url)
                if parsed.scheme.lower() not in ["http", "https"]:
                    flags.append({
                        "name": "Invalid Protocol Scheme",
                        "severity": "HIGH",
                        "reason": f"Redirect chain attempted to switch to non-HTTP protocol '{parsed.scheme}'."
                    })
                    break

                if is_private_target(parsed.hostname or ""):
                    flags.append({
                        "name": "Private IP / Internal SSRF Blocked",
                        "severity": "CRITICAL",
                        "reason": f"Redirect attempt to private/internal network target '{parsed.hostname}' was blocked."
                    })
                    break

                try:
                    response = client.head(current_url)
                    # If server rejects HEAD, fallback to GET
                    if response.status_code in [405, 501]:
                        response = client.get(current_url)
                except httpx.RequestError:
                    # Fallback attempt with GET if HEAD fails
                    try:
                        response = client.get(current_url)
                    except Exception:
                        break

                status = response.status_code
                redirect_chain.append({"url": current_url, "status_code": status})

                # Check redirect status codes (301, 302, 303, 307, 308)
                if status in [301, 302, 303, 307, 308] and "location" in response.headers:
                    next_location = response.headers["location"]
                    # Handle relative URLs
                    if not next_location.startswith(("http://", "https://")):
                        next_location = httpx.URL(current_url).join(next_location).raw.decode("utf-8")
                    current_url = next_location
                else:
                    break
    except Exception as err:
        # Graceful failure if network is unreachable
        pass

    redirect_count = max(0, len(redirect_chain) - 1)
    initial_host = (urlparse(start_url).hostname or "").lower()
    final_host = (urlparse(current_url).hostname or "").lower()
    
    # Strip leading 'www.' for root domain comparison
    init_root = initial_host[4:] if initial_host.startswith("www.") else initial_host
    final_root = final_host[4:] if final_host.startswith("www.") else final_host

    cross_domain = (init_root != final_root) if (init_root and final_root) else False

    if redirect_count >= 3:
        flags.append({
            "name": "Multiple Redirect Hops",
            "severity": "MEDIUM",
            "reason": f"URL redirected {redirect_count} times before reaching final destination."
        })

    if cross_domain and redirect_count > 0:
        flags.append({
            "name": "Cross-Domain Redirect Switch",
            "severity": "HIGH",
            "reason": f"URL redirected from initial host '{initial_host}' to entirely different host '{final_host}'."
        })

    return {
        "redirect_count": redirect_count,
        "redirect_chain": redirect_chain,
        "final_url": current_url,
        "cross_domain_redirect": cross_domain,
        "flags": flags
    }
