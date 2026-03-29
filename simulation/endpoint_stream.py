"""
Simulated endpoint event stream for MalwareScope demo.
Generates realistic endpoint/filesystem/process events with periodic anomaly injection.
"""

import random
import time
from dataclasses import dataclass, field
from typing import Callable

SYSTEM_PROCESSES = [
    "svchost.exe", "explorer.exe", "lsass.exe",
    "winlogon.exe", "csrss.exe", "wininit.exe",
]
SUSPICIOUS_PROCESSES = [
    "powershell.exe", "cmd.exe", "wscript.exe",
    "cscript.exe", "mshta.exe", "regsvr32.exe",
]
TEMP_PATHS = [
    "C:\\Users\\Public\\", "C:\\Windows\\Temp\\",
    "%APPDATA%\\Roaming\\", "%LOCALAPPDATA%\\Temp\\",
]
PERSISTENCE_PATHS = [
    "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\",
    "C:\\Users\\Public\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\",
]


@dataclass
class EndpointEvent:
    timestamp: float
    event_type: str  # process_start | file_create | file_delete | registry_write | anomaly
    process: str
    parent_process: str
    path: str
    user: str
    suspicious: bool
    anomaly_type: str = ""
    details: dict = field(default_factory=dict)


def _normal_event() -> EndpointEvent:
    proc = random.choice(SYSTEM_PROCESSES)
    return EndpointEvent(
        timestamp=time.time(),
        event_type=random.choice(["process_start", "file_create", "registry_write"]),
        process=proc,
        parent_process="System",
        path=f"C:\\Windows\\System32\\{proc}",
        user="SYSTEM",
        suspicious=False,
    )


def _dropper_event() -> EndpointEvent:
    filename = "".join(random.choices("abcdefghijklmnop", k=8)) + ".exe"
    drop_path = random.choice(TEMP_PATHS) + filename
    return EndpointEvent(
        timestamp=time.time(),
        event_type="anomaly",
        process=random.choice(SUSPICIOUS_PROCESSES),
        parent_process=random.choice(SUSPICIOUS_PROCESSES),
        path=drop_path,
        user=random.choice(["user1", "DESKTOP-ABC123\\user"]),
        suspicious=True,
        anomaly_type="dropper_activity",
        details={
            "file_created": drop_path,
            "file_size": random.randint(50000, 500000),
            "entropy": round(random.uniform(7.0, 7.9), 2),
        },
    )


def _persistence_event() -> EndpointEvent:
    persistence_target = random.choice(PERSISTENCE_PATHS)
    return EndpointEvent(
        timestamp=time.time(),
        event_type="anomaly",
        process="cmd.exe",
        parent_process="wscript.exe",
        path=persistence_target,
        user=random.choice(["user1", "SYSTEM"]),
        suspicious=True,
        anomaly_type="persistence_installation",
        details={
            "registry_key": persistence_target,
            "value_name": "WindowsUpdate",
            "value_data": "C:\\Users\\Public\\svchost32.exe",
            "technique": "T1547.001 — Registry Run Keys",
        },
    )


def _lsass_dump_event() -> EndpointEvent:
    return EndpointEvent(
        timestamp=time.time(),
        event_type="anomaly",
        process="taskmgr.exe",
        parent_process="cmd.exe",
        path="C:\\Windows\\Temp\\lsass.dmp",
        user=random.choice(["user1", "Administrator"]),
        suspicious=True,
        anomaly_type="credential_access",
        details={
            "target_process": "lsass.exe",
            "technique": "T1003.001 — LSASS Memory",
            "dump_file": "C:\\Windows\\Temp\\lsass.dmp",
        },
    )


ANOMALY_GENERATORS = [_dropper_event, _persistence_event, _lsass_dump_event]


def stream_events(
    on_event: Callable[[EndpointEvent], None],
    anomaly_interval_seconds: int = 55,
    normal_event_interval_seconds: float = 1.5,
    stop_flag: list = None,
) -> None:
    """
    Continuously generate endpoint events.
    Calls on_event(event) for each event.
    Injects one anomaly every ~anomaly_interval_seconds seconds.
    """
    if stop_flag is None:
        stop_flag = [False]

    last_anomaly = time.time()

    while not stop_flag[0]:
        now = time.time()

        if now - last_anomaly >= anomaly_interval_seconds:
            anomaly_fn = random.choice(ANOMALY_GENERATORS)
            event = anomaly_fn()
            on_event(event)
            last_anomaly = now
        else:
            event = _normal_event()
            on_event(event)

        time.sleep(normal_event_interval_seconds + random.uniform(-0.3, 0.3))
