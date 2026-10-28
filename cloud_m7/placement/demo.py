"""Shared placement comparison for the dashboard; results are model estimates."""
from dataclasses import asdict
from cloud_m7.placement.cost_model import ForensicTask, MultiObjectiveWeights, TaskType
from cloud_m7.placement.optimizer import PlacementOptimizer
from cloud_m7.schema.types import TierType


def placement_comparison():
    profiles = [(150, 64, 500), (120, 48, 500), (350, 180, 200),
                (600, 512, 100), (1200, 1024, 50), (200, 2048, 50)]
    tasks = [ForensicTask(task, *profile) for task, profile in zip(TaskType, profiles)]
    optimizer = PlacementOptimizer(MultiObjectiveWeights(), 800.0, 512.0)
    assignment, metrics = optimizer.find_optimal_placement(tasks)
    baseline = {task.name: TierType.CLOUD for task in tasks}
    baseline[TaskType.EVENT_CAPTURE] = TierType.EDGE
    return {"measurement_kind": "Cost-model estimates; not measured network traffic or device resource use",
        "assumptions": {"edge_cpu_limit_mcore": 800, "edge_memory_limit_mb": 512,
            "input_events_per_second": 500, "bytes_per_event": 512},
        "assignment": {key.value: value.value for key, value in assignment.items()},
        "adaptive": asdict(metrics), "centralized": asdict(optimizer.evaluate_placement(tasks, baseline))}
