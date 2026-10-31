"""
Track 1: simulated eBPF/HPC records and a software HMAC example.
Adapted from DharshiniPES/cloud-m7 (23ba5ed). No kernel or TPM is accessed.
"""

import hashlib
import hmac
import random
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional


@dataclass
class EbpfKernelProbeRecord:
    hook_name: str
    pid: int
    tgid: int
    uid: int
    timestamp_ns: int
    syscall_name: str
    return_code: int
    kernel_stack_depth: int
    inode: Optional[int] = None
    target_resource: str = ""
    is_anomaly: bool = False


@dataclass
class HardwarePerformanceCounters:
    instructions_retired: int
    cpu_cycles: int
    l1_dcache_misses: int
    l2_cache_misses: int
    branch_instructions: int
    branch_mispredictions: int
    ipc: float  # Instructions Per Cycle
    cache_miss_rate: float
    branch_mispredict_rate: float
    is_microarchitectural_anomaly: bool = False
    anomaly_reason: str = "Nominal microarchitectural state"


@dataclass
class TpmMeasurementQuote:
    pcr_index: int
    pcr_digest: str
    nonce: str
    firmware_measurement: str
    tpm_signature: str
    attestation_verified: bool


class EbpfHpcTelemetryEngine:
    """
    Simulates in-kernel eBPF LSM hooks (eBPF ring buffers) and
    Hardware Performance Counter profiles without accessing perf_event_open.
    """

    def __init__(self, tpm_secret: bytes = b"public_demo_key_not_a_hardware_identity", random_seed: int = 42):
        self.tpm_secret = tpm_secret
        self.rng = random.Random(random_seed)
        self.pcr_register_10 = hashlib.sha256(b"init_pcr10_secure_boot_baseline").hexdigest()

    def capture_ebpf_lsm_event(
        self,
        hook_name: str = "security_socket_connect",
        pid: int = 1402,
        syscall_name: str = "sys_enter_connect",
        target_resource: str = "10.0.1.1:8080",
        is_exploit: bool = False,
    ) -> EbpfKernelProbeRecord:
        """Captures in-kernel probe event from simulated eBPF ring buffer."""
        ts_ns = int(time.time() * 1e9)
        return EbpfKernelProbeRecord(
            hook_name=hook_name,
            pid=pid,
            tgid=pid,
            uid=0 if is_exploit else 1000,
            timestamp_ns=ts_ns,
            syscall_name=syscall_name,
            return_code=0,
            kernel_stack_depth=14 if is_exploit else 6,
            inode=self.rng.randint(100000, 999999),
            target_resource=target_resource,
            is_anomaly=is_exploit,
        )

    def sample_hardware_counters(
        self, is_under_attack: bool = False, baseline_instructions: int = 1_500_000
    ) -> HardwarePerformanceCounters:
        """
        Generates a synthetic counter profile; does not sample PMU registers.
        """
        if is_under_attack:
            # Memory exploitation causes heavy pipeline stalls and cache pollution
            instructions = baseline_instructions + self.rng.randint(100_000, 300_000)
            cycles = int(instructions * self.rng.uniform(2.5, 4.2))
            l1_misses = int(instructions * self.rng.uniform(0.18, 0.32))
            l2_misses = int(l1_misses * self.rng.uniform(0.40, 0.65))
            branches = int(instructions * 0.22)
            branch_mispredicts = int(branches * self.rng.uniform(0.12, 0.25))
            anomaly = True
            reason = "Simulated exploit profile selected from supplied scenario labels"
        else:
            # Nominal execution
            instructions = baseline_instructions + self.rng.randint(10_000, 50_000)
            cycles = int(instructions * self.rng.uniform(0.8, 1.2))
            l1_misses = int(instructions * self.rng.uniform(0.01, 0.03))
            l2_misses = int(l1_misses * self.rng.uniform(0.10, 0.20))
            branches = int(instructions * 0.18)
            branch_mispredicts = int(branches * self.rng.uniform(0.01, 0.03))
            anomaly = False
            reason = "Simulated nominal profile"

        ipc = round(instructions / max(cycles, 1), 3)
        cache_miss_rate = round((l1_misses / max(instructions, 1)) * 100.0, 2)
        branch_mispredict_rate = round((branch_mispredicts / max(branches, 1)) * 100.0, 2)

        return HardwarePerformanceCounters(
            instructions_retired=instructions,
            cpu_cycles=cycles,
            l1_dcache_misses=l1_misses,
            l2_cache_misses=l2_misses,
            branch_instructions=branches,
            branch_mispredictions=branch_mispredicts,
            ipc=ipc,
            cache_miss_rate=cache_miss_rate,
            branch_mispredict_rate=branch_mispredict_rate,
            is_microarchitectural_anomaly=anomaly,
            anomaly_reason=reason,
        )

    def generate_tpm2_quote(
        self, event_hash: str, nonce: Optional[str] = None
    ) -> TpmMeasurementQuote:
        """
        Demonstrates hash extension and software HMAC; no TPM quote is obtained.
        """
        nonce = nonce or hashlib.sha256(str(time.time_ns()).encode()).hexdigest()[:16]

        # PCR Extension: PCR_new = SHA256(PCR_old || event_hash)
        extension_payload = (self.pcr_register_10 + event_hash).encode()
        self.pcr_register_10 = hashlib.sha256(extension_payload).hexdigest()

        firmware_msmt = hashlib.sha256(b"arm_cortex_a72_rpi4_bootloader_secure").hexdigest()[:32]

        quote_data = f"{self.pcr_register_10}|{nonce}|{firmware_msmt}".encode()
        tpm_sig = hmac.new(self.tpm_secret, quote_data, hashlib.sha256).hexdigest()

        return TpmMeasurementQuote(
            pcr_index=10,
            pcr_digest=self.pcr_register_10,
            nonce=nonce,
            firmware_measurement=firmware_msmt,
            tpm_signature=tpm_sig,
            attestation_verified=False,
        )

    def get_full_telemetry_snapshot(self, is_attack_scenario: bool = True) -> Dict[str, Any]:
        """Provides a complete JSON-ready telemetry payload for the dashboard."""
        ebpf_event = self.capture_ebpf_lsm_event(
            hook_name="security_socket_connect" if is_attack_scenario else "sys_enter_read",
            pid=3192 if is_attack_scenario else 1024,
            syscall_name="connect" if is_attack_scenario else "sys_read",
            target_resource="10.0.1.1:8080" if is_attack_scenario else "/var/log/sensor.dat",
            is_exploit=is_attack_scenario,
        )
        hpc = self.sample_hardware_counters(is_under_attack=is_attack_scenario)
        tpm = self.generate_tpm2_quote(event_hash=hashlib.sha256(ebpf_event.target_resource.encode()).hexdigest())

        return {
            "mode": "simulation_only",
            "hardware_capture": False,
            "description": "Generated scenario profiles; no eBPF, perf counter or TPM access.",
            "ebpf_lsm": {
                "hook_name": ebpf_event.hook_name,
                "syscall": ebpf_event.syscall_name,
                "pid": ebpf_event.pid,
                "uid": ebpf_event.uid,
                "stack_depth": ebpf_event.kernel_stack_depth,
                "target_resource": ebpf_event.target_resource,
                "is_anomaly": ebpf_event.is_anomaly,
                "timestamp_ns": ebpf_event.timestamp_ns,
            },
            "hpc_registers": {
                "instructions": hpc.instructions_retired,
                "cycles": hpc.cpu_cycles,
                "ipc": hpc.ipc,
                "l1_misses": hpc.l1_dcache_misses,
                "l2_misses": hpc.l2_cache_misses,
                "cache_miss_rate_pct": hpc.cache_miss_rate,
                "branch_mispredict_pct": hpc.branch_mispredict_rate,
                "is_anomaly": hpc.is_microarchitectural_anomaly,
                "reason": hpc.anomaly_reason,
            },
            "tpm_attestation": {
                "pcr_index": tpm.pcr_index,
                "pcr_digest": tpm.pcr_digest[:16] + "...",
                "nonce": tpm.nonce,
                "firmware_hash": tpm.firmware_measurement,
                "signature": tpm.tpm_signature[:24] + "...",
                "verified": tpm.attestation_verified,
            },
        }
