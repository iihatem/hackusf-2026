"""
Simulated network event stream for MalwareScope demo.
Generates realistic network traffic with periodic anomaly injection.
One meaningful anomaly every ~45-60 seconds (configurable).
"""

import random
import time
from dataclasses import dataclass, field
from typing import Callable

INTERNAL_HOSTS = [
    "192.168.1.10", "192.168.1.20", "192.168.1.30",
    "192.168.1.50", "10.0.0.5", "10.0.0.10",
]
EXTERNAL_BENIGN = [
    "8.8.8.8", "1.1.1.1", "204.79.197.200",  # DNS, Cloudflare, Microsoft
    "151.101.65.69",  # Fastly CDN
]
SUSPICIOUS_IPS = [
    "185.220.101.47", "194.165.16.11", "91.108.4.0",
    "45.142.212.100", "104.21.0.0",
]
SUSPICIOUS_DOMAINS = [
    "update-service.club", "cdn-static.xyz", "telemetry-hub.net",
    "config-sync.io", "beacon.darkpulse.cc",
]
NORMAL_DOMAINS = [
    "microsoft.com", "windowsupdate.com", "office.com",
    "google.com", "amazonaws.com",
]


@dataclass
class NetworkEvent:
    timestamp: float
    event_type: str  # dns_query | tcp_connection | http_request | anomaly
    src_ip: str
    dst_ip: str
    dst_port: int
    protocol: str
    domain: str
    payload_size: int
    suspicious: bool
    anomaly_type: str = ""
    details: dict = field(default_factory=dict)


def _normal_event() -> NetworkEvent:
    src = random.choice(INTERNAL_HOSTS)
    domain = random.choice(NORMAL_DOMAINS)
    return NetworkEvent(
        timestamp=time.time(),
        event_type=random.choice(["dns_query", "tcp_connection", "http_request"]),
        src_ip=src,
        dst_ip=random.choice(EXTERNAL_BENIGN),
        dst_port=random.choice([80, 443, 53, 8080]),
        protocol=random.choice(["TCP", "UDP", "HTTPS"]),
        domain=domain,
        payload_size=random.randint(200, 4000),
        suspicious=False,
    )


def _c2_beacon_event() -> NetworkEvent:
    src = random.choice(INTERNAL_HOSTS)
    dst = random.choice(SUSPICIOUS_IPS)
    return NetworkEvent(
        timestamp=time.time(),
        event_type="anomaly",
        src_ip=src,
        dst_ip=dst,
        dst_port=random.choice([443, 8443, 4444, 1337]),
        protocol="TCP",
        domain="",
        payload_size=random.randint(128, 512),
        suspicious=True,
        anomaly_type="c2_beacon",
        details={
            "beacon_interval": f"{random.randint(30, 120)}s",
            "encrypted_payload": True,
            "user_agent": "Mozilla/5.0 (compatible; MSIE 9.0)",
        },
    )


def _dns_exfil_event() -> NetworkEvent:
    subdomain = "".join(random.choices("abcdefghijklmnop0123456789", k=20))
    domain = random.choice(SUSPICIOUS_DOMAINS)
    return NetworkEvent(
        timestamp=time.time(),
        event_type="anomaly",
        src_ip=random.choice(INTERNAL_HOSTS),
        dst_ip="8.8.8.8",
        dst_port=53,
        protocol="UDP",
        domain=f"{subdomain}.{domain}",
        payload_size=random.randint(60, 250),
        suspicious=True,
        anomaly_type="dns_exfiltration",
        details={
            "subdomain_length": len(subdomain),
            "entropy": round(random.uniform(3.5, 4.5), 2),
            "dga_suspected": True,
        },
    )


def _lateral_movement_event() -> NetworkEvent:
    src = random.choice(INTERNAL_HOSTS)
    dst = random.choice([h for h in INTERNAL_HOSTS if h != src])
    return NetworkEvent(
        timestamp=time.time(),
        event_type="anomaly",
        src_ip=src,
        dst_ip=dst,
        dst_port=random.choice([445, 135, 5985, 22]),
        protocol="TCP",
        domain="",
        payload_size=random.randint(500, 2000),
        suspicious=True,
        anomaly_type="lateral_movement",
        details={
            "service": random.choice(["SMB", "WMI", "WinRM", "SSH"]),
            "authentication_attempt": True,
            "pass_the_hash": random.choice([True, False]),
        },
    )


ANOMALY_GENERATORS = [_c2_beacon_event, _dns_exfil_event, _lateral_movement_event]


def stream_events(
    on_event: Callable[[NetworkEvent], None],
    anomaly_interval_seconds: int = 50,
    normal_event_interval_seconds: float = 2.0,
    stop_flag: list = None,
) -> None:
    """
    Continuously generate network events.
    Calls on_event(event) for each generated event.
    Injects one anomaly every ~anomaly_interval_seconds seconds.
    stop_flag: pass a list with one element [False]; set it to [True] to stop.
    """
    if stop_flag is None:
        stop_flag = [False]

    last_anomaly = time.time()

    while not stop_flag[0]:
        now = time.time()

        # Inject anomaly if interval elapsed
        if now - last_anomaly >= anomaly_interval_seconds:
            anomaly_fn = random.choice(ANOMALY_GENERATORS)
            event = anomaly_fn()
            on_event(event)
            last_anomaly = now
        else:
            event = _normal_event()
            on_event(event)

        time.sleep(normal_event_interval_seconds + random.uniform(-0.5, 0.5))
