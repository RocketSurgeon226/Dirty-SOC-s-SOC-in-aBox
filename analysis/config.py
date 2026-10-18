"""Owner: Brady — Load settings (paths, thresholds, LLM on/off) from config/settings.yaml.

Usage:

    from analysis.config import load_settings
    settings = load_settings()
    settings.detectors.tracker_dns.max_queries  # -> 20

Defaults live in the dataclasses below (matching config/settings.example.yaml);
settings.yaml only needs overrides, and may be absent.

The API key comes only from $ANTHROPIC_API_KEY, never YAML, so it can't be
committed by accident.
"""

from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass, field, fields, is_dataclass
from pathlib import Path
from typing import Any, Optional, Union, get_args, get_origin, get_type_hints

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_SETTINGS_PATH = REPO_ROOT / "config" / "settings.yaml"
SETTINGS_PATH_ENV = "SOC_SETTINGS"  #optional override for the settings file path
API_KEY_ENV = "ANTHROPIC_API_KEY"


class ConfigError(ValueError):
    """Raised when settings.yaml has an unknown key or an invalid value."""


@dataclass
class PathSettings:
    eve_json: Path = Path("/var/log/suricata/eve.json")
    database: Path = Path("data/soc_in_a_box.db")
    tracker_domains: Path = Path("threat_intel/tracker_domains.txt")


@dataclass
class NetworkSettings:
    home_networks: list[str] = field(
        default_factory=lambda: ["192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12"]
    )
    capture_interface: str = "eth1"

    def is_home_ip(self, ip: str) -> bool:
        """True if ip falls inside one of the home networks."""
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in net for net in self._parsed_networks())

    def _parsed_networks(self) -> list[ipaddress._BaseNetwork]:
        return [ipaddress.ip_network(n, strict=False) for n in self.home_networks]


@dataclass
class DedupSettings:
    window_minutes: int = 15


@dataclass
class TrackerDnsSettings:
    max_queries: int = 20
    window_minutes: int = 5


@dataclass
class OutboundVolumeSettings:
    multiplier: float = 3.0
    baseline_window_minutes: int = 60
    min_bytes: int = 10_000_000


@dataclass
class NewDeviceSettings:
    enabled: bool = True


@dataclass
class DetectorSettings:
    tracker_dns: TrackerDnsSettings = field(default_factory=TrackerDnsSettings)
    outbound_volume: OutboundVolumeSettings = field(default_factory=OutboundVolumeSettings)
    new_device: NewDeviceSettings = field(default_factory=NewDeviceSettings)


@dataclass
class LlmSettings:
    enabled: bool = False
    model: str = "claude-opus-5-5"
    timeout_seconds: float = 10
    api_key: Optional[str] = field(default=None, repr=False)  #from ANTHROPIC_API_KEY only

    @property
    def usable(self) -> bool:
        """True only if the LLM is turned on and there's a key to call it with."""
        return self.enabled and bool(self.api_key)


@dataclass
class RetentionSettings:
    days: int = 30


@dataclass
class DashboardSettings:
    host: str = "0.0.0.0"
    port: int = 8080


@dataclass
class Settings:
    paths: PathSettings = field(default_factory=PathSettings)
    network: NetworkSettings = field(default_factory=NetworkSettings)
    dedup: DedupSettings = field(default_factory=DedupSettings)
    detectors: DetectorSettings = field(default_factory=DetectorSettings)
    llm: LlmSettings = field(default_factory=LlmSettings)
    retention: RetentionSettings = field(default_factory=RetentionSettings)
    dashboard: DashboardSettings = field(default_factory=DashboardSettings)


def load_settings(path: Optional[Union[str, Path]] = None) -> Settings:
    """Load settings from YAML on top of the defaults.

    Path order: `path`, $SOC_SETTINGS, config/settings.yaml. Only an explicitly
    requested file is an error if missing.
    """
    explicit = path or os.environ.get(SETTINGS_PATH_ENV)
    settings_path = Path(explicit) if explicit else DEFAULT_SETTINGS_PATH

    if settings_path.exists():
        with settings_path.open() as f:
            data = yaml.safe_load(f) or {}
    elif explicit:
        raise ConfigError(f"Settings file not found: {settings_path}")
    else:
        data = {}

    if not isinstance(data, dict):
        raise ConfigError(f"{settings_path} must contain a YAML mapping at the top level")

    settings = _build(Settings, data, "settings")
    settings.llm.api_key = os.environ.get(API_KEY_ENV) or None
    _resolve_paths(settings.paths)
    _validate(settings)
    return settings


def _build(cls: type, data: dict[str, Any], where: str) -> Any:
    """Build dataclass `cls` from `data`, recursing into nested sections."""
    hints = get_type_hints(cls)
    known = {f.name for f in fields(cls) if f.name != "api_key"}
    unknown = set(data) - known
    if unknown:
        raise ConfigError(f"Unknown key(s) in {where}: {', '.join(sorted(unknown))}")

    kwargs = {}
    for name, value in data.items():
        kwargs[name] = _coerce(hints[name], value, f"{where}.{name}")
    return cls(**kwargs)


def _coerce(hint: Any, value: Any, where: str) -> Any:
    """Convert a YAML value to the field's declared type, or raise ConfigError."""
    if get_origin(hint) is Union:  # Optional[X]
        if value is None:
            return None
        hint = next(a for a in get_args(hint) if a is not type(None))

    if is_dataclass(hint):
        if value is None:
            return hint()
        if not isinstance(value, dict):
            raise ConfigError(f"{where} must be a section (mapping), got {value!r}")
        return _build(hint, value, where)

    if get_origin(hint) is list:
        if not isinstance(value, list):
            raise ConfigError(f"{where} must be a list, got {value!r}")
        (item_type,) = get_args(hint)
        return [_coerce(item_type, v, f"{where}[{i}]") for i, v in enumerate(value)]

    #bool is a subclass of int, so check it before the numeric cases.
    if hint is bool:
        if not isinstance(value, bool):
            raise ConfigError(f"{where} must be true or false, got {value!r}")
        return value
    if hint in (int, float):
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ConfigError(f"{where} must be a number, got {value!r}")
        if hint is int and not float(value).is_integer():
            raise ConfigError(f"{where} must be a whole number, got {value!r}")
        return hint(value)
    if hint is str:
        if not isinstance(value, (str, int, float)) or isinstance(value, bool):
            raise ConfigError(f"{where} must be text, got {value!r}")
        return str(value)
    if hint is Path:
        if not isinstance(value, str):
            raise ConfigError(f"{where} must be a path, got {value!r}")
        return Path(value).expanduser()

    raise ConfigError(f"{where}: unsupported setting type {hint!r}")


def _resolve_paths(paths: PathSettings) -> None:
    """Make relative paths relative to the repo root, not the current directory."""
    for f in fields(paths):
        p = getattr(paths, f.name)
        if not p.is_absolute():
            setattr(paths, f.name, REPO_ROOT / p)


def _validate(s: Settings) -> None:
    for net in s.network.home_networks:
        try:
            ipaddress.ip_network(net, strict=False)
        except ValueError:
            raise ConfigError(f"network.home_networks: {net!r} is not a valid network") from None

    positive = {
        "dedup.window_minutes": s.dedup.window_minutes,
        "detectors.tracker_dns.max_queries": s.detectors.tracker_dns.max_queries,
        "detectors.tracker_dns.window_minutes": s.detectors.tracker_dns.window_minutes,
        "detectors.outbound_volume.baseline_window_minutes":
            s.detectors.outbound_volume.baseline_window_minutes,
        "llm.timeout_seconds": s.llm.timeout_seconds,
        "retention.days": s.retention.days,
    }
    for name, value in positive.items():
        if value <= 0:
            raise ConfigError(f"{name} must be greater than 0, got {value}")

    if s.detectors.outbound_volume.multiplier <= 1:
        raise ConfigError(
            "detectors.outbound_volume.multiplier must be greater than 1, "
            f"got {s.detectors.outbound_volume.multiplier}"
        )
    if s.detectors.outbound_volume.min_bytes < 0:
        raise ConfigError("detectors.outbound_volume.min_bytes must be 0 or more")
    if not 1 <= s.dashboard.port <= 65535:
        raise ConfigError(f"dashboard.port must be 1-65535, got {s.dashboard.port}")
