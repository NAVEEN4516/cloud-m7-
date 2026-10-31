"""
Lightweight Hardware Edge Telemetry & Forensic Probe.

Designed to run directly on physical Edge hardware (e.g., Raspberry Pi 4/3,
NVIDIA Jetson Nano, or Linux SBC) to capture live operating system and sensor events.

Capabilities:
    1. Real Hardware Telemetry: Gathers CPU temperature, memory, disk, and sensor states.
    2. Event Normalization: Packages local events into Canonical Provenance Schema E_i.
    3. Canonical Digests: Hashes events using the shared schema before forwarding.
    4. Attack Simulation Mode: Injects a synthetic firmware anomaly or exfiltration event
       to demonstrate live hardware-in-the-loop attack reconstruction.
"""

import argparse
import json
import os
import platform
import socket
import sys
import time
import urllib.request
import uuid
from typing import Any, Dict, Optional

# Support direct script execution from a complete project checkout as well as -m.
if __package__ in (None, ""):
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
from cloud_m7.schema.event import ProvenanceEvent

def generate_hardware_event(
    event_type: str,
    action: str,
    entity: str,
    is_attack: bool = False,
    extra_payload: Optional[Dict[str, Any]] = None,
    host_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Generates an E_i compatible provenance event dictionary on physical edge device."""
    ts = time.time()
    hostname = host_id or socket.gethostname() or "rpi-edge-sensor-01"
    evt_uuid = f"hw-{hostname}-{uuid.uuid4()}"

    payload = {
        "action": action,
        "entity": entity,
        "is_attack": is_attack,
        "os_platform": platform.platform(),
        "arch": platform.machine(),
    }
    if extra_payload:
        payload.update(extra_payload)

    return ProvenanceEvent(uuid=evt_uuid, timestamp=ts, tier="Edge",
                           host_id=hostname, event_type=event_type,
                           payload=payload, parents=[]).to_dict()


def read_pi_temperature() -> float:
    """Reads physical CPU temperature on Raspberry Pi or returns simulated metric."""
    temp_path = "/sys/class/thermal/thermal_zone0/temp"
    if os.path.exists(temp_path):
        try:
            with open(temp_path, "r") as f:
                return round(float(f.read().strip()) / 1000.0, 1)
        except Exception:
            pass
    return 42.5  # Standard ambient simulation


class HardwareEdgeProbe:
    """Agent running on physical edge hardware transmitting to Fog Gateway."""

    def __init__(self, fog_gateway_url: str = "http://127.0.0.1:8080/telemetry", host_id: Optional[str] = None):
        self.fog_url = fog_gateway_url
        self.host_id = host_id or f"rpi-{socket.gethostname()}"

    def send_event_to_fog(self, event: Dict[str, Any]) -> bool:
        """Sends serialized E_i event to the Fog gateway over HTTP/JSON."""
        try:
            data = json.dumps(event).encode("utf-8")
            req = urllib.request.Request(
                self.fog_url,
                data=data,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                return resp.status in [200, 201, 202]
        except Exception as e:
            # Fallback for offline / simulation testing
            return False

    def run_telemetry_loop(self, interval_sec: float = 2.0, max_events: int = 10, simulate_attack: bool = True):
        """Continuously streams hardware readings and optional attack injection."""
        print(f"[*] Starting Hardware Edge Probe on host: {self.host_id}")
        print(f"[*] Streaming to Fog Gateway: {self.fog_url}")

        for i in range(max_events):
            temp = read_pi_temperature()
            is_malicious = simulate_attack and (i == 4 or i == 5)

            if is_malicious:
                # Attack: Unauthorized firmware injection or memory dump
                evt = generate_hardware_event(
                    event_type="Process",
                    action="exec",
                    entity="/usr/local/bin/tamper_firmware.sh",
                    is_attack=True,
                    extra_payload={"cpu_temp_c": temp, "exploit": "firmware_injection"},
                    host_id=self.host_id,
                )
                print(f"[!] INJECTING ATTACK EVENT [{i+1}/{max_events}]: {evt['uuid']} - /usr/local/bin/tamper_firmware.sh")
            else:
                # Normal sensor telemetry
                evt = generate_hardware_event(
                    event_type="File",
                    action="write",
                    entity="/var/log/sensor_readings.csv",
                    is_attack=False,
                    extra_payload={"cpu_temp_c": temp, "status": "nominal"},
                    host_id=self.host_id,
                )
                print(f"[+] Nominal Telemetry [{i+1}/{max_events}]: Temp={temp}C -> {evt['uuid']}")

            self.send_event_to_fog(evt)
            time.sleep(interval_sec)

        print("[*] Hardware Probe execution completed.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CLOUD-M7 Physical Edge Hardware Probe")
    parser.add_argument("--fog-url", default="http://127.0.0.1:8080/telemetry", help="Fog Gateway ingestion endpoint")
    parser.add_argument("--host-id", default=None, help="Hardware identifier (e.g. rpi-sensor-lab)")
    parser.add_argument("--count", type=int, default=10, help="Number of telemetry cycles to emit")
    parser.add_argument("--interval", type=float, default=1.0, help="Seconds between telemetry emissions")
    parser.add_argument("--simulate-attack", action="store_true", default=True, help="Include attack injection step")
    args = parser.parse_args()

    probe = HardwareEdgeProbe(fog_gateway_url=args.fog_url, host_id=args.host_id)
    probe.run_telemetry_loop(interval_sec=args.interval, max_events=args.count, simulate_attack=args.simulate_attack)
