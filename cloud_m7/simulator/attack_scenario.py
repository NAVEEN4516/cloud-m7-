"""
Multi-Stage Attack and Benign Telemetry Generator.

Simulates the concrete multi-tier attack progression:
    Edge Sensor Compromise -> Fog Gateway Lateral Pivot -> Cloud Data Exfiltration
Intermingled with benign background operational telemetry across all tiers.
"""

import time
import uuid
from typing import List, Optional, Tuple
from cloud_m7.schema.event import ProvenanceEvent
from cloud_m7.schema.types import EventType, TierType
from cloud_m7.simulator.topology import MultiTierTopology


class MultiTierAttackSimulator:
    """
    Generates synthetic high-fidelity multi-tier provenance events conforming
    to the CLOUD-M7 schema tuple specification.
    """

    def __init__(self, topology: MultiTierTopology = MultiTierTopology()):
        self.topology = topology

    def generate_benign_events(
        self, base_time: float, num_events: int = 30
    ) -> List[ProvenanceEvent]:
        """
        Generates benign operational events (sensors reporting telemetry,
        fog gateways polling heartbeats, cloud maintenance jobs).
        """
        events: List[ProvenanceEvent] = []
        t = base_time

        # 1. Edge regular sensor reads
        for i in range(num_events // 3):
            t += 0.5
            p_read = ProvenanceEvent(
                uuid=f"benign-edge-read-{i}",
                timestamp=t,
                tier=TierType.EDGE,
                host_id="edge-sensor-01",
                event_type=EventType.FILE,
                payload={
                    "action": "read",
                    "entity": "/sys/class/thermal/thermal_zone0/temp",
                    "process": "sensor_daemon",
                    "pid": 1042,
                    "is_attack": False,
                    "description": "Benign periodic thermal sensor reading",
                },
            )
            events.append(p_read)

            t += 0.2
            # Outbound benign report to Fog
            p_sock_out = ProvenanceEvent(
                uuid=f"benign-edge-sock-out-{i}",
                timestamp=t,
                tier=TierType.EDGE,
                host_id="edge-sensor-01",
                event_type=EventType.SOCKET,
                payload={
                    "action": "send",
                    "src_ip": "192.168.1.50",
                    "src_port": 39000 + i,
                    "dst_ip": "10.0.1.1",
                    "dst_port": 1883,
                    "protocol": "TCP",
                    "bytes": 128,
                    "is_attack": False,
                    "description": "MQTT periodic metric publish to Fog gateway",
                },
                parents=[p_read.uuid],
            )
            events.append(p_sock_out)

        # 2. Fog benign aggregation
        for i in range(num_events // 3):
            t += 0.4
            p_fog_agg = ProvenanceEvent(
                uuid=f"benign-fog-agg-{i}",
                timestamp=t,
                tier=TierType.FOG,
                host_id="fog-gateway-01",
                event_type=EventType.PROCESS,
                payload={
                    "action": "exec",
                    "entity": "iot_aggregator",
                    "pid": 2180,
                    "is_attack": False,
                    "description": "Aggregating regional sensor timeseries metrics",
                },
            )
            events.append(p_fog_agg)

        # 3. Cloud benign audit healthcheck
        for i in range(num_events // 3):
            t += 0.6
            p_cloud_hc = ProvenanceEvent(
                uuid=f"benign-cloud-audit-{i}",
                timestamp=t,
                tier=TierType.CLOUD,
                host_id="cloud-api-prod",
                event_type=EventType.API,
                payload={
                    "action": "query_db",
                    "entity": "/healthz",
                    "user": "kube-probe",
                    "is_attack": False,
                    "description": "Kubernetes liveness and readiness probe check",
                },
            )
            events.append(p_cloud_hc)

        return events

    def generate_attack_scenario(self, base_time: float) -> List[ProvenanceEvent]:
        """
        Synthesizes the complete multi-tier cyberattack chain:
            Stage 1: Edge Sensor Compromise
            Stage 2: Fog Gateway Lateral Pivot
            Stage 3: Cloud Database Exfiltration
        """
        attack_events: List[ProvenanceEvent] = []
        t = base_time + 5.0

        # ==========================================
        # STAGE 1: Edge Sensor Compromise
        # ==========================================
        # Step 1.1: Vulnerable IoT agent receives remote buffer overflow exploit
        e1_edge_exploit = ProvenanceEvent(
            uuid="atk-edge-01-exploit",
            timestamp=t,
            tier=TierType.EDGE,
            host_id="edge-sensor-01",
            event_type=EventType.PROCESS,
            payload={
                "action": "exec",
                "entity": "/usr/bin/iot_agent",
                "pid": 1102,
                "is_attack": True,
                "description": "Vulnerable IoT agent memory corruption exploit triggered",
            },
        )
        attack_events.append(e1_edge_exploit)

        # Step 1.2: Exploit spawns malicious /bin/sh shell
        t += 0.3
        e2_edge_shell = ProvenanceEvent(
            uuid="atk-edge-02-shell",
            timestamp=t,
            tier=TierType.EDGE,
            host_id="edge-sensor-01",
            event_type=EventType.PROCESS,
            payload={
                "action": "fork",
                "entity": "/bin/sh",
                "pid": 1188,
                "is_attack": True,
                "description": "Shell process spawned with elevated root privileges",
            },
            parents=[e1_edge_exploit.uuid],
        )
        attack_events.append(e2_edge_shell)

        # Step 1.3: Attacker drops reconnaissance beacon script to /tmp
        t += 0.4
        e3_edge_drop = ProvenanceEvent(
            uuid="atk-edge-03-drop",
            timestamp=t,
            tier=TierType.EDGE,
            host_id="edge-sensor-01",
            event_type=EventType.FILE,
            payload={
                "action": "write",
                "entity": "/tmp/.pivot_beacon.sh",
                "size_bytes": 4096,
                "is_attack": True,
                "description": "Dropped staging lateral-movement script on local filesystem",
            },
            parents=[e2_edge_shell.uuid],
        )
        attack_events.append(e3_edge_drop)

        # Step 1.4: Attacker reads stored gateway credentials
        t += 0.2
        e4_edge_creds = ProvenanceEvent(
            uuid="atk-edge-04-creds",
            timestamp=t,
            tier=TierType.EDGE,
            host_id="edge-sensor-01",
            event_type=EventType.FILE,
            payload={
                "action": "read",
                "entity": "/etc/iot/fog_gateway_token.key",
                "is_attack": True,
                "description": "Exfiltrated internal Fog gateway authentication token",
            },
            parents=[e3_edge_drop.uuid],
        )
        attack_events.append(e4_edge_creds)

        # Step 1.5: Outbound network socket from Edge to Fog Gateway
        t += 0.5
        e5_edge_sock_out = ProvenanceEvent(
            uuid="atk-edge-05-socket-out",
            timestamp=t,
            tier=TierType.EDGE,
            host_id="edge-sensor-01",
            event_type=EventType.SOCKET,
            payload={
                "action": "connect",
                "src_ip": "192.168.1.50",
                "src_port": 48210,
                "dst_ip": "10.0.1.1",
                "dst_port": 8080,
                "protocol": "TCP",
                "is_attack": True,
                "description": "Outbound lateral movement TCP socket initiated to Fog gateway",
            },
            parents=[e4_edge_creds.uuid],
        )
        attack_events.append(e5_edge_sock_out)

        # ==========================================
        # STAGE 2: Fog Gateway Lateral Pivot
        # ==========================================
        # Step 2.1: Fog Gateway accepts incoming socket (Cross-tier link E_network)
        t += 0.015  # Network transit delay (~15ms)
        e6_fog_sock_in = ProvenanceEvent(
            uuid="atk-fog-01-socket-in",
            timestamp=t,
            tier=TierType.FOG,
            host_id="fog-gateway-01",
            event_type=EventType.SOCKET,
            payload={
                "action": "accept",
                "src_ip": "192.168.1.50",
                "src_port": 48210,
                "dst_ip": "10.0.1.1",
                "dst_port": 8080,
                "protocol": "TCP",
                "is_attack": True,
                "description": "Fog gateway accepts rogue session using stolen token",
            },
        )
        attack_events.append(e6_fog_sock_in)

        # Step 2.2: Gateway spawns malicious remote command process
        t += 0.4
        e7_fog_spawn = ProvenanceEvent(
            uuid="atk-fog-02-exec",
            timestamp=t,
            tier=TierType.FOG,
            host_id="fog-gateway-01",
            event_type=EventType.PROCESS,
            payload={
                "action": "exec",
                "entity": "/usr/bin/python3 -c 'import os; os.system(\"scrape_creds\")'",
                "pid": 3410,
                "is_attack": True,
                "description": "Unauthorized Python process executed on Fog gateway",
            },
            parents=[e6_fog_sock_in.uuid],
        )
        attack_events.append(e7_fog_spawn)

        # Step 2.3: Scrapes Cloud IAM service role secrets
        t += 0.3
        e8_fog_scrape = ProvenanceEvent(
            uuid="atk-fog-03-cloud-creds",
            timestamp=t,
            tier=TierType.FOG,
            host_id="fog-gateway-01",
            event_type=EventType.FILE,
            payload={
                "action": "read",
                "entity": "/var/run/secrets/cloud_service_account.json",
                "is_attack": True,
                "description": "Read privileged Cloud service-account token from Fog node",
            },
            parents=[e7_fog_spawn.uuid],
        )
        attack_events.append(e8_fog_scrape)

        # Step 2.4: Outbound HTTPS socket from Fog Gateway to Cloud API
        t += 0.6
        e9_fog_sock_out = ProvenanceEvent(
            uuid="atk-fog-04-socket-out",
            timestamp=t,
            tier=TierType.FOG,
            host_id="fog-gateway-01",
            event_type=EventType.SOCKET,
            payload={
                "action": "connect",
                "src_ip": "10.0.1.1",
                "src_port": 52110,
                "dst_ip": "172.16.0.10",
                "dst_port": 443,
                "protocol": "TCP",
                "is_attack": True,
                "description": "Outbound pivot connection to centralized Cloud API endpoint",
            },
            parents=[e8_fog_scrape.uuid],
        )
        attack_events.append(e9_fog_sock_out)

        # ==========================================
        # STAGE 3: Cloud Data Exfiltration
        # ==========================================
        # Step 3.1: Cloud API accepts incoming socket (Cross-tier link E_network)
        t += 0.065  # WAN transit delay (~65ms)
        e10_cloud_sock_in = ProvenanceEvent(
            uuid="atk-cloud-01-socket-in",
            timestamp=t,
            tier=TierType.CLOUD,
            host_id="cloud-api-prod",
            event_type=EventType.SOCKET,
            payload={
                "action": "accept",
                "src_ip": "10.0.1.1",
                "src_port": 52110,
                "dst_ip": "172.16.0.10",
                "dst_port": 443,
                "protocol": "TCP",
                "is_attack": True,
                "description": "Cloud API ingress receives connection carrying stolen token",
            },
        )
        attack_events.append(e10_cloud_sock_in)

        # Step 3.2: Malicious API invocation to extract confidential records
        t += 0.5
        e11_cloud_api = ProvenanceEvent(
            uuid="atk-cloud-02-api-call",
            timestamp=t,
            tier=TierType.CLOUD,
            host_id="cloud-api-prod",
            event_type=EventType.API,
            payload={
                "action": "auth_login",
                "entity": "POST /v1/admin/export_customer_data",
                "token_id": "service-account-fog-cluster",
                "is_attack": True,
                "description": "Unauthorized administrative API request invoked",
            },
            parents=[e10_cloud_sock_in.uuid],
        )
        attack_events.append(e11_cloud_api)

        # Step 3.3: Cloud database query dumping 50,000 sensitive records
        t += 0.8
        e12_cloud_db = ProvenanceEvent(
            uuid="atk-cloud-03-db-query",
            timestamp=t,
            tier=TierType.CLOUD,
            host_id="cloud-db-cluster",
            event_type=EventType.API,
            payload={
                "action": "query_db",
                "entity": "SELECT * FROM enterprise_customer_records WHERE sensitive=true",
                "records_affected": 50000,
                "is_attack": True,
                "description": "Mass extraction of confidential database records",
            },
            parents=[e11_cloud_api.uuid],
        )
        attack_events.append(e12_cloud_db)

        # Step 3.4: Archiving dumped data into local staging archive
        t += 0.7
        e13_cloud_dump = ProvenanceEvent(
            uuid="atk-cloud-04-file-archive",
            timestamp=t,
            tier=TierType.CLOUD,
            host_id="cloud-api-prod",
            event_type=EventType.FILE,
            payload={
                "action": "write",
                "entity": "/tmp/exfiltrated_records_dump.tar.gz",
                "size_bytes": 104857600,  # 100 MB
                "is_attack": True,
                "description": "Customer database records packed into compressed archive",
            },
            parents=[e12_cloud_db.uuid],
        )
        attack_events.append(e13_cloud_dump)

        # Step 3.5: Final Exfiltration to External C2 Server
        t += 1.2
        e14_cloud_exfil = ProvenanceEvent(
            uuid="atk-cloud-05-exfil-c2",
            timestamp=t,
            tier=TierType.CLOUD,
            host_id="cloud-api-prod",
            event_type=EventType.SOCKET,
            payload={
                "action": "exfil_data",
                "src_ip": "172.16.0.10",
                "src_port": 59912,
                "dst_ip": "198.51.100.77",
                "dst_port": 443,
                "protocol": "TCP",
                "bytes_transferred": 104857600,
                "is_attack": True,
                "description": "CRITICAL IMPACT: Sensitive data exfiltrated to adversary C2 IP",
            },
            parents=[e13_cloud_dump.uuid],
        )
        attack_events.append(e14_cloud_exfil)

        return attack_events

    def generate_secondary_attack_vector(
        self, base_time: float, primary_events: List[ProvenanceEvent]
    ) -> List[ProvenanceEvent]:
        """
        Synthesizes a secondary, concurrent attack vector:
            Secondary Edge Device (edge-sensor-02) Firmware Exploit ->
            Secondary Fog Gateway Persistence Backdoor
        Demonstrates multi-root attack discovery across iterations.
        """
        secondary_events: List[ProvenanceEvent] = []
        t = base_time + 6.0  # Concurrent timeline

        # Step 2.1: Vulnerable firmware updater on edge-sensor-02
        v2_edge_exploit = ProvenanceEvent(
            uuid="atk2-edge-01-fw-exploit",
            timestamp=t,
            tier=TierType.EDGE,
            host_id="edge-sensor-02",
            event_type=EventType.PROCESS,
            payload={
                "action": "exec",
                "entity": "/usr/sbin/fw_updater",
                "pid": 890,
                "is_attack": True,
                "description": "Secondary IoT sensor firmware command-injection exploit",
            },
        )
        secondary_events.append(v2_edge_exploit)

        # Step 2.2: Exploit spawns reverse shell
        t += 0.3
        v2_edge_shell = ProvenanceEvent(
            uuid="atk2-edge-02-shell",
            timestamp=t,
            tier=TierType.EDGE,
            host_id="edge-sensor-02",
            event_type=EventType.PROCESS,
            payload={
                "action": "fork",
                "entity": "/bin/sh",
                "pid": 912,
                "is_attack": True,
                "description": "Stealth shell spawned on secondary edge sensor",
            },
            parents=[v2_edge_exploit.uuid],
        )
        secondary_events.append(v2_edge_shell)

        # Step 2.3: Outbound socket from edge-sensor-02 to Fog Gateway (port 9090)
        t += 0.4
        v2_edge_sock_out = ProvenanceEvent(
            uuid="atk2-edge-03-socket-out",
            timestamp=t,
            tier=TierType.EDGE,
            host_id="edge-sensor-02",
            event_type=EventType.SOCKET,
            payload={
                "action": "connect",
                "src_ip": "192.168.1.51",
                "src_port": 49100,
                "dst_ip": "10.0.1.1",
                "dst_port": 9090,
                "protocol": "TCP",
                "is_attack": True,
                "description": "Secondary lateral movement socket to Fog gateway port 9090",
            },
            parents=[v2_edge_shell.uuid],
        )
        secondary_events.append(v2_edge_sock_out)

        # Step 2.4: Fog Gateway accepts incoming socket (Cross-tier link E_network)
        t += 0.02
        v2_fog_sock_in = ProvenanceEvent(
            uuid="atk2-fog-01-socket-in",
            timestamp=t,
            tier=TierType.FOG,
            host_id="fog-gateway-01",
            event_type=EventType.SOCKET,
            payload={
                "action": "accept",
                "src_ip": "192.168.1.51",
                "src_port": 49100,
                "dst_ip": "10.0.1.1",
                "dst_port": 9090,
                "protocol": "TCP",
                "is_attack": True,
                "description": "Fog gateway accepts secondary covert connection",
            },
        )
        secondary_events.append(v2_fog_sock_in)

        # Step 2.5: Fog gateway backdoor links to the Fog unauthorized python process
        # (Connects this secondary vector to the primary pivot chain)
        t += 0.3
        # Find primary fog execution event to establish causal link
        primary_fog_exec = next(
            (e for e in primary_events if e.uuid == "atk-fog-02-exec"), None
        )
        parent_ids = [v2_fog_sock_in.uuid]
        if primary_fog_exec:
            parent_ids.append(primary_fog_exec.uuid)

        v2_fog_persist = ProvenanceEvent(
            uuid="atk2-fog-02-persist",
            timestamp=t,
            tier=TierType.FOG,
            host_id="fog-gateway-01",
            event_type=EventType.FILE,
            payload={
                "action": "write",
                "entity": "/etc/cron.d/stealth_persist",
                "is_attack": True,
                "description": "Secondary persistence task established on Fog gateway",
            },
            parents=parent_ids,
        )
        secondary_events.append(v2_fog_persist)

        # Also link persistence to downstream cloud socket if available
        primary_cloud_sock = next(
            (e for e in primary_events if e.uuid == "atk-fog-04-socket-out"), None
        )
        if primary_cloud_sock:
            primary_cloud_sock.add_parent(v2_fog_persist.uuid)

        # ==============================================================
        # Vector 3: Industrial Actuator (edge-actuator-03) Modbus Exploit
        # ==============================================================
        # Third source must arrive before the shared fog execution, not after it.
        t = base_time + 6.1
        v3_edge_exploit = ProvenanceEvent(
            uuid="atk3-edge-01-plc-exploit",
            timestamp=t,
            tier=TierType.EDGE,
            host_id="edge-actuator-03",
            event_type=EventType.PROCESS,
            payload={
                "action": "exec",
                "entity": "/usr/bin/modbus_controller",
                "pid": 504,
                "is_attack": True,
                "description": "Unauthorized industrial actuator Modbus control injection",
            },
        )
        secondary_events.append(v3_edge_exploit)

        t += 0.2
        v3_edge_sock_out = ProvenanceEvent(
            uuid="atk3-edge-02-socket-out",
            timestamp=t,
            tier=TierType.EDGE,
            host_id="edge-actuator-03",
            event_type=EventType.SOCKET,
            payload={
                "action": "connect",
                "src_ip": "192.168.1.52",
                "src_port": 50200,
                "dst_ip": "10.0.1.1",
                "dst_port": 1883,
                "protocol": "TCP",
                "is_attack": True,
                "description": "Outbound rogue telemetry flow from actuator to Fog gateway",
            },
            parents=[v3_edge_exploit.uuid],
        )
        secondary_events.append(v3_edge_sock_out)

        t += 0.015
        v3_fog_sock_in = ProvenanceEvent(
            uuid="atk3-fog-01-socket-in",
            timestamp=t,
            tier=TierType.FOG,
            host_id="fog-gateway-01",
            event_type=EventType.SOCKET,
            payload={
                "action": "accept",
                "src_ip": "192.168.1.52",
                "src_port": 50200,
                "dst_ip": "10.0.1.1",
                "dst_port": 1883,
                "protocol": "TCP",
                "is_attack": True,
                "description": "Fog gateway ingress accepts connection from corrupted actuator",
            },
        )
        secondary_events.append(v3_fog_sock_in)

        # Link to fog execution
        if primary_fog_exec:
            primary_fog_exec.add_parent(v3_fog_sock_in.uuid)

        return secondary_events

    def generate_full_simulation_dataset(
        self,
        base_time: Optional[float] = None,
        benign_count: int = 40,
        include_multi_vector: bool = True,
    ) -> List[ProvenanceEvent]:
        """
        Combines background benign workloads with the multi-stage cyberattack,
        optionally adding a secondary concurrent attack vector for iterative discovery.
        """
        if base_time is None:
            base_time = time.time()

        benign = self.generate_benign_events(base_time=base_time, num_events=benign_count)
        attack_primary = self.generate_attack_scenario(base_time=base_time)

        all_events = benign + attack_primary

        if include_multi_vector:
            attack_secondary = self.generate_secondary_attack_vector(
                base_time=base_time, primary_events=attack_primary
            )
            all_events.extend(attack_secondary)

        # Sort chronologically by timestamp
        all_events.sort(key=lambda e: e.timestamp)
        return all_events

