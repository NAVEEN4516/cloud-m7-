"""Strict, lossless ingestion for the controlled Review 2 JSON/CSV format."""
import csv
import io
import json
import math

from cloud_m7.schema.event import ProvenanceEvent


class DatasetValidationError(ValueError):
    def __init__(self, errors):
        self.errors = errors
        super().__init__("; ".join(errors))


def parse_canonical(content):
    """Return native events, or None when this is an external dataset format."""
    stripped = content.lstrip()
    if stripped.startswith(("[", "{")):
        try:
            records = json.loads(content)
        except json.JSONDecodeError as exc:
            raise DatasetValidationError([f"JSON line {exc.lineno}: {exc.msg}"]) from exc
        if isinstance(records, dict):
            records = [records]
        if not records:
            raise DatasetValidationError(["Dataset is empty"])
        if not isinstance(records, list) or not isinstance(records[0], dict):
            raise DatasetValidationError(["Expected a JSON array of event objects"])
        if not {"tier", "host_id"}.intersection(records[0]):
            return None
    else:
        reader = csv.DictReader(io.StringIO(content))
        if not reader.fieldnames or not {"uuid", "tier", "payload_json"}.intersection(reader.fieldnames):
            return None
        records = list(reader)
        if not records:
            raise DatasetValidationError(["CSV has no event rows"])
    events, errors, seen = [], [], set()
    positions = {}
    for index, record in enumerate(records, 1):
        try:
            if not isinstance(record, dict):
                raise ValueError("Expected an event object")
            row = dict(record)
            for key in ("uuid", "timestamp", "tier", "host_id", "event_type"):
                if key not in row or row[key] is None or row[key] == "":
                    raise ValueError(f"Missing required field '{key}'")
            if not isinstance(row["uuid"], str) or not isinstance(row["host_id"], str):
                raise ValueError("uuid and host_id must be strings")
            if row["uuid"] in seen:
                raise ValueError(f"Duplicate UUID '{row['uuid']}'")
            row["timestamp"] = float(row["timestamp"])
            if not math.isfinite(row["timestamp"]):
                raise ValueError("timestamp must be finite Unix seconds")
            if "payload_json" in row:
                row["payload"] = json.loads(row.pop("payload_json"))
            if "parents_json" in row:
                row["parents"] = json.loads(row.pop("parents_json"))
            if not isinstance(row.get("payload"), dict):
                raise ValueError("payload must be an object (CSV: payload_json)")
            if not isinstance(row.get("parents"), list) or not all(isinstance(p, str) for p in row["parents"]):
                raise ValueError("parents must be an array of UUID strings (CSV: parents_json)")
            if "is_attack" in row["payload"] and not isinstance(row["payload"]["is_attack"], bool):
                raise ValueError("payload.is_attack must be a JSON boolean")
            supplied_hash = row.get("tamper_hash") or None
            row["tamper_hash"] = supplied_hash
            event = ProvenanceEvent.from_dict(row)
            if supplied_hash and supplied_hash != event.compute_integrity_hash():
                raise ValueError("Integrity hash does not match event contents")
            if event.is_network_event:
                for key in ("src_ip", "src_port", "dst_ip", "dst_port", "protocol"):
                    if key not in event.payload:
                        raise ValueError(f"Socket payload missing '{key}'")
                for key in ("src_port", "dst_port"):
                    if not 1 <= int(event.payload[key]) <= 65535:
                        raise ValueError(f"Invalid {key}")
            seen.add(event.uuid)
            events.append(event)
            positions[event.uuid] = index
        except (ValueError, TypeError, KeyError) as exc:
            errors.append(f"Row {index}: {exc}")
    for event in events:
        for parent in event.parents:
            if parent not in seen:
                errors.append(f"Row {positions[event.uuid]}: missing parent '{parent}'")
    if errors:
        raise DatasetValidationError(errors)
    return events
