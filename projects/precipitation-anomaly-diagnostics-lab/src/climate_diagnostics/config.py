from __future__ import annotations

from pathlib import Path
from typing import Any


def load_config(path: str | Path) -> dict[str, Any]:
    """Load a YAML configuration file."""
    try:
        import yaml
    except ImportError as exc:
        raise RuntimeError("PyYAML is required. Install with: python -m pip install -e .") from exc

    cfg_path = Path(path)
    with cfg_path.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    if not isinstance(data, dict):
        raise ValueError(f"Config root must be a mapping: {cfg_path}")
    return data


def cfg_get(cfg: dict[str, Any], dotted: str, default: Any = None) -> Any:
    """Read a nested config value using dotted keys."""
    cur: Any = cfg
    for part in dotted.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return default
        cur = cur[part]
    return cur


def project_root(cfg: dict[str, Any], config_path: str | Path) -> Path:
    """Return the project root declared by the config, resolved from the config folder."""
    cfg_path = Path(config_path).resolve()
    root_value = cfg_get(cfg, "project.root", "..")
    root_path = Path(root_value).expanduser()
    if root_path.is_absolute():
        return root_path.resolve()
    return (cfg_path.parent / root_path).resolve()


def resolve_path(cfg: dict[str, Any], config_path: str | Path, dotted: str, required: bool = True) -> Path | None:
    """Resolve a path setting relative to project.root."""
    value = cfg_get(cfg, dotted)
    if value in (None, ""):
        if required:
            raise ValueError(f"Missing required config path: {dotted}")
        return None
    path = Path(str(value)).expanduser()
    if path.is_absolute():
        return path
    return (project_root(cfg, config_path) / path).resolve()


def output_dir(cfg: dict[str, Any], config_path: str | Path, *parts: str) -> Path:
    """Return and create the configured output directory."""
    base = resolve_path(cfg, config_path, "paths.output_dir", required=False)
    if base is None:
        base = project_root(cfg, config_path) / "outputs"
    out = base.joinpath(*parts)
    out.mkdir(parents=True, exist_ok=True)
    return out
