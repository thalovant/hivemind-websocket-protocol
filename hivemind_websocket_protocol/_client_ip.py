"""Client-IP resolution for listeners running behind a trusted proxy."""
import ipaddress
from typing import Iterable, Mapping, Optional, Tuple, Union

from ovos_utils.log import LOG

IPNetwork = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]


def parse_networks(cidrs: Iterable[str]) -> Tuple[IPNetwork, ...]:
    nets = []
    for cidr in cidrs:
        try:
            nets.append(ipaddress.ip_network(cidr, strict=False))
        except ValueError:
            LOG.warning(f"hivemind: ignoring invalid trusted proxy CIDR: {cidr!r}")
    return tuple(nets)


def _in_networks(ip: str, networks: Tuple[IPNetwork, ...]) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in networks)


def resolve_client_ip(
    remote_ip: Optional[str],
    headers: Mapping[str, str],
    trusted_networks: Tuple[IPNetwork, ...],
    trusted_headers: Tuple[str, ...],
) -> Optional[str]:
    """Return the real client IP.

    Headers are only consulted when the direct peer is in a trusted proxy CIDR.
    For chains (comma-separated values, e.g. X-Forwarded-For), walk right-to-left
    and return the first address that is not itself a trusted proxy.
    """
    if not remote_ip or not _in_networks(remote_ip, trusted_networks):
        return remote_ip

    for header in trusted_headers:
        raw = headers.get(header)
        if not raw:
            continue
        candidates = []
        for value in raw.split(","):
            value = value.strip()
            if not value:
                continue
            try:
                ipaddress.ip_address(value)
            except ValueError:
                continue  # skip "unknown", port-suffixed, garbage
            candidates.append(value)
        for candidate in reversed(candidates):
            if not _in_networks(candidate, trusted_networks):
                return candidate
    return remote_ip
