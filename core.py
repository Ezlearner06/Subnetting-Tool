#!/usr/bin/env python3
"""
SubnetLab — Core Network Logic
Pure Python 3. No external dependencies.
This module contains all IP/subnet calculation functions.
"""


def validate_ip(ip: str) -> bool:
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    for p in parts:
        if not p.isdigit():
            return False
        v = int(p)
        if v < 0 or v > 255:
            return False
    return True


def parse_input(raw: str):
    """Return (ip_str, prefix_len) or raise ValueError."""
    raw = raw.strip()
    if not raw:
        raise ValueError("Empty input")

    # Format: IP/CIDR
    if "/" in raw:
        parts = raw.split("/")
        ip_str = parts[0].strip()
        try:
            prefix = int(parts[1].strip())
        except ValueError:
            raise ValueError("Invalid CIDR prefix")
        if prefix < 0 or prefix > 32:
            raise ValueError("Prefix must be 0-32")
        if not validate_ip(ip_str):
            raise ValueError("Invalid IP address")
        return ip_str, prefix

    # Format: IP MASK (space separated)
    tokens = raw.split()
    if len(tokens) == 2 and validate_ip(tokens[0]) and validate_ip(tokens[1]):
        ip_str = tokens[0]
        mask_int = ip_to_int(tokens[1])
        # Validate mask: must be contiguous 1s followed by 0s
        inv = (~mask_int) & 0xFFFFFFFF
        if (inv & (inv + 1)) != 0:
            raise ValueError("Invalid subnet mask (non-contiguous)")
        prefix = bin(mask_int).count("1")
        return ip_str, prefix

    # Format: IP only → derive prefix from class
    if validate_ip(raw):
        cls = classify_ip(raw)
        return raw, cls["default_prefix"]

    raise ValueError("Unrecognised format. Use IP/CIDR, IP MASK, or just IP.")


def classify_ip(ip: str) -> dict:
    first = int(ip.split(".")[0])
    if first == 0:
        return {"class": "A", "range": "0.0.0.0 – 0.255.255.255",
                "default_prefix": 8, "default_mask": "255.0.0.0",
                "description": "This Network", "special": "this_network"}
    if first == 127:
        return {"class": "A", "range": "127.0.0.0 – 127.255.255.255",
                "default_prefix": 8, "default_mask": "255.0.0.0",
                "description": "Loopback", "special": "loopback"}
    if 1 <= first <= 126:
        return {"class": "A", "range": "1.0.0.0 – 126.255.255.255",
                "default_prefix": 8, "default_mask": "255.0.0.0",
                "description": "Large networks (16M hosts)",
                "private_range": "10.0.0.0 – 10.255.255.255"}
    if 128 <= first <= 191:
        return {"class": "B", "range": "128.0.0.0 – 191.255.255.255",
                "default_prefix": 16, "default_mask": "255.255.0.0",
                "description": "Medium networks (65K hosts)",
                "private_range": "172.16.0.0 – 172.31.255.255"}
    if 192 <= first <= 223:
        return {"class": "C", "range": "192.0.0.0 – 223.255.255.255",
                "default_prefix": 24, "default_mask": "255.255.255.0",
                "description": "Small networks (254 hosts)",
                "private_range": "192.168.0.0 – 192.168.255.255"}
    if 224 <= first <= 239:
        return {"class": "D", "range": "224.0.0.0 – 239.255.255.255",
                "default_prefix": 4, "default_mask": "240.0.0.0",
                "description": "Multicast", "special": "multicast"}
    # 240-255
    return {"class": "E", "range": "240.0.0.0 – 255.255.255.255",
            "default_prefix": 4, "default_mask": "240.0.0.0",
            "description": "Reserved / Experimental", "special": "reserved"}


def ip_to_int(ip: str) -> int:
    octets = ip.split(".")
    return (int(octets[0]) << 24) | (int(octets[1]) << 16) | (int(octets[2]) << 8) | int(octets[3])


def int_to_ip(n: int) -> str:
    return f"{(n >> 24) & 0xFF}.{(n >> 16) & 0xFF}.{(n >> 8) & 0xFF}.{n & 0xFF}"


def cidr_to_mask(prefix: int) -> str:
    if prefix == 0:
        return "0.0.0.0"
    mask = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
    return int_to_ip(mask)


def wildcard_mask(prefix: int) -> str:
    mask_int = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
    inv = (~mask_int) & 0xFFFFFFFF
    return int_to_ip(inv)


def calculate_network_id(ip: str, prefix: int) -> str:
    mask_int = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
    net = ip_to_int(ip) & mask_int
    return int_to_ip(net)


def calculate_broadcast(ip: str, prefix: int) -> str:
    mask_int = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
    net = ip_to_int(ip) & mask_int
    inv = (~mask_int) & 0xFFFFFFFF
    return int_to_ip(net | inv)


def to_binary_str(ip: str) -> str:
    return ".".join(f"{int(o):08b}" for o in ip.split("."))


def to_binary_octets(ip: str) -> list:
    return [f"{int(o):08b}" for o in ip.split(".")]


def host_id(ip: str, prefix: int) -> str:
    mask_int = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
    host = ip_to_int(ip) & (~mask_int & 0xFFFFFFFF)
    return int_to_ip(host)


def is_private(ip: str) -> bool:
    n = ip_to_int(ip)
    if (n >> 24) == 10:
        return True
    if (n >> 20) == 0xAC1:
        return True
    if (n >> 16) == 0xC0A8:
        return True
    return False


def is_loopback(ip: str) -> bool:
    return int(ip.split(".")[0]) == 127


def is_apipa(ip: str) -> bool:
    parts = ip.split(".")
    return int(parts[0]) == 169 and int(parts[1]) == 254


def is_multicast(ip: str) -> bool:
    f = int(ip.split(".")[0])
    return 224 <= f <= 239


def analyze_ip(ip: str, prefix: int) -> dict:
    """Perform full subnet analysis and return a result dict."""
    mask = cidr_to_mask(prefix)
    wc_mask = wildcard_mask(prefix)
    net_addr = calculate_network_id(ip, prefix)
    bcast = calculate_broadcast(ip, prefix)
    cls_info = classify_ip(ip)
    host_bits = 32 - prefix
    total_hosts = 2 ** host_bits
    usable = max(total_hosts - 2, 0) if prefix < 31 else (1 if prefix == 31 else 0)

    if prefix == 32:
        first_usable = ip
        last_usable = ip
        usable = 1
    elif prefix == 31:
        first_usable = net_addr
        last_usable = bcast
        usable = 2
    else:
        first_usable = int_to_ip(ip_to_int(net_addr) + 1)
        last_usable = int_to_ip(ip_to_int(bcast) - 1)

    h_id = host_id(ip, prefix)

    return {
        "ip": ip, "prefix": prefix, "mask": mask, "wildcard": wc_mask,
        "network": net_addr, "broadcast": bcast, "cls": cls_info,
        "host_bits": host_bits, "total_hosts": total_hosts,
        "usable_hosts": usable, "first_usable": first_usable,
        "last_usable": last_usable, "host_id": h_id,
    }
