"""Candidate STIX export and measured in-memory event-time aggregation.

Adapted from DharshiniPES/cloud-m7 (23ba5ed). Export checks are structural,
not STIX schema certification or a tested SIEM integration. Streaming is a
single-process reference implementation, not a distributed service benchmark.
"""
import json
import math
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, List


@dataclass
class StixThreatIntelBundle:
    bundle_id: str
    spec_version: str
    objects_count: int
    threat_actor_id: str
    campaign_id: str
    attack_pattern_ids: List[str]
    course_of_action_id: str
    stix_json_string: str
    validation_status: str


@dataclass
class StreamingWatermarkMetrics:
    events_ingested: int
    throughput_events_per_sec: float
    tumbling_window_size_sec: float
    watermark_delay_ms: float
    dropped_late_events: int
    windows_processed: int
    events_received: int
    processing_time_ms: float
    watermark_timestamp: float | None
    window_counts: Dict[str, int]
    measurement_kind: str = 'Measured in-memory Python aggregation; excludes network and storage'


class StixThreatIntelGenerator:
    def generate_stix_bundle(self, reconstructed_steps, choke_point_node=None,
                             mitre_techniques=None):
        now = datetime.now(timezone.utc).isoformat(timespec='milliseconds').replace('+00:00', 'Z')
        def object_for(kind, name, **extra):
            return {'type': kind, 'spec_version': '2.1', 'id': f'{kind}--{uuid.uuid4()}',
                    'created': now, 'modified': now, 'name': name, **extra}
        def relationship(source, target, kind):
            return {'type': 'relationship', 'spec_version': '2.1',
                    'id': f'relationship--{uuid.uuid4()}', 'created': now, 'modified': now,
                    'relationship_type': kind, 'source_ref': source, 'target_ref': target}
        objects, patterns = [], []
        campaign_id = coa_id = ''
        if reconstructed_steps:
            campaign = object_for('campaign', 'Reconstructed activity from supplied evidence',
                                  description='No real actor attribution is inferred by this prototype.')
            campaign_id = campaign['id']
            objects.append(campaign)
            for step in reconstructed_steps:
                references = [{'source_name': 'mitre-attack', 'external_id': m['technique_id']}
                              for m in (mitre_techniques or [])
                              if m.get('evidence_uuid') == step.get('uuid') and m.get('technique_id')]
                pattern = object_for(
                    'attack-pattern', f"[{step.get('tier', '')}] {step.get('action', 'event')}",
                    description=f"Evidence {step.get('uuid', '')} on {step.get('host_id', '')}: {step.get('entity', '')}")
                if references:
                    pattern['external_references'] = references
                objects.append(pattern)
                patterns.append(pattern['id'])
                objects.append(relationship(campaign_id, pattern['id'], 'uses'))
            for first, second in zip(patterns, patterns[1:]):
                objects.append(relationship(first, second, 'related-to'))
            if choke_point_node:
                coa = object_for('course-of-action', f'Proposed isolation of {choke_point_node}',
                                 description='Graph-derived proposal only; no containment was deployed.')
                coa_id = coa['id']
                objects.append(coa)
                for pattern_id in patterns:
                    objects.append(relationship(coa_id, pattern_id, 'mitigates'))
        bundle = {'type': 'bundle', 'id': f'bundle--{uuid.uuid4()}', 'objects': objects}
        self.validate_bundle_structure(bundle)
        return StixThreatIntelBundle(
            bundle['id'], '2.1', len(objects), '', campaign_id, patterns, coa_id,
            json.dumps(bundle, indent=2), 'structural_checks_passed; external_interoperability_unverified')

    @staticmethod
    def validate_bundle_structure(bundle):
        """Check IDs, basic required fields and internal relationship references."""
        if bundle.get('type') != 'bundle' or not isinstance(bundle.get('objects'), list):
            raise ValueError('Expected a bundle and object list')
        identifiers = set()
        for item in [bundle] + bundle['objects']:
            kind, identifier = item.get('type'), item.get('id', '')
            if not kind or not identifier.startswith(f'{kind}--'):
                raise ValueError('Object type/ID mismatch')
            uuid.UUID(identifier.split('--', 1)[1])
            if identifier in identifiers:
                raise ValueError('Duplicate object ID')
            identifiers.add(identifier)
            if kind != 'bundle' and not all(item.get(k) for k in ('spec_version', 'created', 'modified')):
                raise ValueError('Missing object metadata')
        object_ids = {item['id'] for item in bundle['objects']}
        for item in bundle['objects']:
            if item['type'] == 'relationship' and (
                item.get('source_ref') not in object_ids or item.get('target_ref') not in object_ids
                or not item.get('relationship_type')):
                raise ValueError('Dangling relationship reference')
        return True


class EventTimeStreamingEngine:
    """Count events in tumbling windows; drop events older than the watermark.

    Watermark = largest observed event timestamp minus allowed lateness. This
    simple policy is explicit; the watermark lag is configuration, not latency.
    """
    def __init__(self, window_size_sec=10.0, allowed_lateness_sec=3.0):
        if (not math.isfinite(window_size_sec) or window_size_sec <= 0
                or not math.isfinite(allowed_lateness_sec) or allowed_lateness_sec < 0):
            raise ValueError('Finite positive window and nonnegative lateness required')
        self.window_size_sec = window_size_sec
        self.allowed_lateness_sec = allowed_lateness_sec

    def process_events(self, events):
        started = time.perf_counter()
        received = accepted = dropped = 0
        maximum = watermark = None
        windows = {}
        for event in events:
            timestamp = float(event['timestamp'])
            if not math.isfinite(timestamp):
                raise ValueError('Event timestamp must be finite')
            received += 1
            if watermark is not None and timestamp < watermark:
                dropped += 1
                continue
            maximum = timestamp if maximum is None else max(maximum, timestamp)
            watermark = maximum - self.allowed_lateness_sec
            bucket = str(math.floor(timestamp / self.window_size_sec))
            windows[bucket] = windows.get(bucket, 0) + 1
            accepted += 1
        elapsed = time.perf_counter() - started
        return StreamingWatermarkMetrics(
            accepted, round(received / elapsed, 1) if elapsed else 0.0,
            self.window_size_sec, self.allowed_lateness_sec * 1000,
            dropped, len(windows), received, round(elapsed * 1000, 6),
            watermark, windows)

    def benchmark_stream_ingestion(self, total_events=50_000):
        if not isinstance(total_events, int) or total_events < 0:
            raise ValueError('total_events must be a nonnegative integer')
        # Generation and consumption both occur within the measured interval.
        return self.process_events({'timestamp': index / 1000} for index in range(total_events))
