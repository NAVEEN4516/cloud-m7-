"""Proof-format simulation adapted from DharshiniPES/cloud-m7 (23ba5ed).

No SNARK backend, circuit, witness or verification key is implemented. Never
interpret this bundle as a cryptographic proof or privacy guarantee.
"""
import hashlib
import json
import time
import uuid
from dataclasses import dataclass
from typing import Dict, List, Optional


@dataclass
class ZkProofBundle:
    proof_id: str
    circuit_name: str
    num_constraints: int
    public_inputs: Dict[str, str]
    proof_pi_a: List[str]
    proof_pi_b: List[List[str]]
    proof_pi_c: List[str]
    verification_time_ms: Optional[float]
    is_valid: bool
    privacy_guarantee: str
    status: str
    generation_time_ms: float


class ZkProvenanceVerifier:
    def __init__(self, curve: str = 'BN254'):
        self.curve = curve

    def generate_zk_proof(self, path_length: int = 0, root_hash: str = '',
                          target_hash: str = '', choke_point_severed: bool = False):
        if path_length < 0:
            raise ValueError('path_length must be nonnegative')
        started = time.perf_counter()
        inputs = {'root_commitment': root_hash, 'target_commitment': target_hash,
                  'containment_claim': str(bool(choke_point_severed)).lower(),
                  'path_hop_depth': str(path_length)}
        # This checksum is an inspectable example, not a zero-knowledge proof.
        checksum = hashlib.sha256(json.dumps(inputs, sort_keys=True).encode()).hexdigest()
        return ZkProofBundle(
            f'demo-proof--{uuid.uuid4()}', 'Unimplemented SNARK circuit', 0, inputs,
            [checksum], [], [], None, False,
            'No zero-knowledge or authenticity guarantee; public-input checksum only.',
            'simulation_only', round((time.perf_counter() - started) * 1000, 3))

    def verify_proof(self, bundle: ZkProofBundle) -> bool:
        """Fail closed: no cryptographic verifier is available for any bundle."""
        return False
