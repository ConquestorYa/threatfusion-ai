from __future__ import annotations

import shutil
from pathlib import Path

from .demo_cti import write_public_demo_cti_cache
from .ml_artifact import train_selected_model_artifact, write_ml_artifact
from .ml_dataset import DomainSample


def build_public_demo_model_samples(
    count_per_label: int = 80,
) -> tuple[DomainSample, ...]:
    """Return deterministic synthetic samples for a demo-only ML artifact."""
    if count_per_label < 30:
        raise ValueError("count_per_label must be at least 30")

    benign = tuple(
        DomainSample(
            domain=f"docs-{index:03d}-portal.example.com",
            label=0,
            source="ThreatFusion Demo",
        )
        for index in range(count_per_label)
    )
    malicious = tuple(
        DomainSample(
            domain=f"xj{index:03d}qz-update-check.biz",
            label=1,
            source="ThreatFusion Demo",
        )
        for index in range(count_per_label)
    )
    return (*benign, *malicious)


def create_public_demo_runtime(
    output_dir: Path,
    *,
    overwrite: bool = False,
) -> tuple[Path, Path]:
    """Create a network-free, synthetic-only runtime for the hosted demo."""
    output = Path(output_dir)
    if output.exists():
        if any(output.iterdir()) and not overwrite:
            raise FileExistsError(
                "public demo runtime is not empty; use overwrite=True"
            )
        if overwrite:
            shutil.rmtree(output)

    output.mkdir(parents=True, exist_ok=True)
    db_path = output / "threatfusion.sqlite"
    model_dir = output / "models" / "development-001"

    write_public_demo_cti_cache(db_path)
    artifact = train_selected_model_artifact(
        build_public_demo_model_samples(),
    )
    write_ml_artifact(artifact, model_dir)

    return db_path, model_dir
