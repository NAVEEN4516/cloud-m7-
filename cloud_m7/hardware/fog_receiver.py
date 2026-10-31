"""
Fog Gateway Hardware Ingestion & Aggregation Server.

Runs on an intermediate hardware node (e.g. Laptop, Mini-PC, or gateway router)
to receive incoming telemetry from physical Edge probes (Raspberry Pis),
aggregate and check canonical SHA-256 digests, and feed the graph engine.
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import threading
from typing import Any, Dict, List, Optional
import time

from cloud_m7.schema.event import ProvenanceEvent
from cloud_m7.schema.types import EventType, TierType


class FogTelemetryHandler(BaseHTTPRequestHandler):
    """HTTP Request Handler for physical Edge telemetry ingestion."""

    received_events: List[ProvenanceEvent] = []

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        post_data = self.rfile.read(content_length)

        try:
            data = json.loads(post_data.decode("utf-8"))
            evt = ProvenanceEvent.from_dict(data)
            if not data.get("tamper_hash") or evt.tamper_hash != evt.compute_integrity_hash():
                raise ValueError("Missing or mismatched canonical event digest")
            FogTelemetryHandler.received_events.append(evt)

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            response = {"status": "accepted", "uuid": evt.uuid, "total_buffered": len(FogTelemetryHandler.received_events)}
            self.wfile.write(json.dumps(response).encode("utf-8"))
        except Exception as e:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(json.dumps({"status": "error", "message": str(e)}).encode("utf-8"))

    def log_message(self, format, *args):
        # Suppress routine log output to keep console clean
        return


class FogHardwareGatewayServer:
    """HTTP Server listening on Fog Gateway for Edge hardware events."""

    def __init__(self, host: str = "0.0.0.0", port: int = 8080):
        self.host = host
        self.port = port
        self.server: Optional[HTTPServer] = None
        self._thread: Optional[threading.Thread] = None

    def start_background(self):
        """Starts server in a background daemon thread."""
        self.server = HTTPServer((self.host, self.port), FogTelemetryHandler)
        self._thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self._thread.start()
        print(f"[+] Fog Gateway Server listening on http://{self.host}:{self.port}/telemetry")

    def stop(self):
        """Stops the gateway server."""
        if self.server:
            self.server.shutdown()
            self.server.server_close()

    @classmethod
    def get_buffered_events(cls) -> List[ProvenanceEvent]:
        """Returns all received hardware events."""
        return list(FogTelemetryHandler.received_events)

    @classmethod
    def clear_buffer(cls):
        """Clears the buffered events."""
        FogTelemetryHandler.received_events.clear()
