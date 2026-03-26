#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import socket
import subprocess
import sys
from datetime import datetime, timezone
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple


IMPACTED_VERSIONS = {"1.82.7", "1.82.8"}
IOC_DOMAIN = "models.litellm.cloud"
SITE_PACKAGES_DIRS = {"site-packages", "dist-packages"}
DEPENDENCY_FILE_NAMES = {
    "pyproject.toml",
    "poetry.lock",
    "uv.lock",
    "pdm.lock",
    "requirements.txt",
    "requirements-dev.txt",
    "requirements-prod.txt",
    "Pipfile",
    "Pipfile.lock",
    "environment.yml",
    "environment.yaml",
    "setup.py",
    "setup.cfg",
}
DEV_ROOT_NAMES = (
    "Projects",
    "Project",
    "Code",
    "Documents",
    "PycharmProjects",
    "WeChatProjects",
    "source",
    "src",
    "repos",
    "workspace",
)
HIDDEN_DEV_ROOT_NAMES = (
    ".langflow",
    ".virtualenvs",
    ".venvs",
    ".pipx",
    ".local",
)
SEARCH_SKIP_NAMES = {
    ".git",
    ".hg",
    ".svn",
    ".Trash",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    ".next",
    ".nuxt",
    "node_modules",
    "target",
    "dist",
    "build",
}
DEPENDENCY_SKIP_NAMES = SEARCH_SKIP_NAMES | {"venv", ".venv", ".conda", "miniconda3", "anaconda3"}
TEXT_FILE_SUFFIXES = {
    ".txt",
    ".log",
    ".json",
    ".jsonl",
    ".yaml",
    ".yml",
    ".toml",
    ".cfg",
    ".conf",
    ".ini",
    ".lock",
    ".env",
    ".md",
    ".rst",
    ".sh",
    ".zsh",
    ".bash",
    ".ps1",
    ".bat",
    ".cmd",
    ".properties",
    ".xml",
}
PROXY_IOC_RE = re.compile(r"models\.litellm\.cloud|openssl pkeyutl|curl -s -o /dev/null -X POST", re.IGNORECASE)
DIST_INFO_RE = re.compile(r"^litellm-(\d+\.\d+\.\d+)\.dist-info$")
GENERIC_VERSION_RE = re.compile(r"\b(\d+\.\d+\.\d+)\b")
LITELLM_RE = re.compile(r"\blitellm\b", re.IGNORECASE)
LITELLM_IMPACTED_RE = re.compile(r"\blitellm\b.*\b1\.82\.(?:7|8)\b|\b1\.82\.(?:7|8)\b.*\blitellm\b", re.IGNORECASE)
MAX_TEXT_BYTES = 2 * 1024 * 1024
GITHUB_REMOTE_RE = re.compile(r"github\.com[:/](?P<slug>[^/\s]+/[^/\s]+?)(?:\.git)?/?$", re.IGNORECASE)


@dataclass
class Finding:
    severity: str
    category: str
    path: str
    detail: str


@dataclass
class ScanReport:
    platform: str
    home: str
    hostname: str
    generated_at_utc: str
    extra_scan_roots: List[str]
    scanned_paths: Set[str] = field(default_factory=set)
    findings: List[Finding] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    counts: Dict[str, int] = field(
        default_factory=lambda: {
            "environment_roots": 0,
            "project_roots": 0,
            "site_packages_dirs": 0,
            "dependency_files": 0,
            "history_files": 0,
            "log_files": 0,
            "docker_objects": 0,
        }
    )
    _dedupe: Set[Tuple[str, str, str, str]] = field(default_factory=set, repr=False)

    def add_finding(self, severity: str, category: str, path: Path, detail: str) -> None:
        key = (severity, category, str(path), detail)
        if key in self._dedupe:
            return
        self._dedupe.add(key)
        self.findings.append(Finding(severity=severity, category=category, path=str(path), detail=detail))

    def add_warning(self, message: str) -> None:
        if message not in self.warnings:
            self.warnings.append(message)

    def remember_path(self, path: Path) -> None:
        self.scanned_paths.add(str(path))


@dataclass(frozen=True)
class AffectedProjectRule:
    label: str
    repo_slugs: Tuple[str, ...] = ()
    dir_names: Tuple[str, ...] = ()
    owner_prefixes: Tuple[str, ...] = ()


@dataclass(frozen=True)
class AffectedProjectsConfig:
    rules: Tuple[AffectedProjectRule, ...]
    ignore_paths: Tuple[str, ...] = ()
    ignore_repo_slugs: Tuple[str, ...] = ()
    ignore_dir_names: Tuple[str, ...] = ()
    ignore_owner_prefixes: Tuple[str, ...] = ()


DEFAULT_AFFECTED_PROJECT_RULES: Tuple[Dict[str, Any], ...] = (
    {"label": "google/adk-python", "repo_slugs": ["google/adk-python"], "dir_names": ["adk-python"]},
    {"label": "stanfordnlp/dspy", "repo_slugs": ["stanfordnlp/dspy"], "dir_names": ["dspy"]},
    {"label": "OpenHands/OpenHands", "repo_slugs": ["openhands/openhands"], "dir_names": ["openhands"]},
    {"label": "guardrails-ai/guardrails", "repo_slugs": ["guardrails-ai/guardrails"], "dir_names": ["guardrails"]},
    {"label": "unclecode/crawl4ai", "repo_slugs": ["unclecode/crawl4ai"], "dir_names": ["crawl4ai"]},
    {"label": "neuml/txtai", "repo_slugs": ["neuml/txtai"], "dir_names": ["txtai"]},
    {"label": "microsoft/agent-framework", "repo_slugs": ["microsoft/agent-framework"], "dir_names": ["agent-framework"]},
    {"label": "getsentry/sentry-python", "repo_slugs": ["getsentry/sentry-python"], "dir_names": ["sentry-python"]},
    {"label": "astronomer/astronomer-cosmos", "repo_slugs": ["astronomer/astronomer-cosmos"], "dir_names": ["astronomer-cosmos"]},
    {"label": "UKGovernmentBEIS/control-arena", "repo_slugs": ["ukgovernmentbeis/control-arena"], "dir_names": ["control-arena"]},
    {"label": "notebook-intelligence/<truncated-from-user-list>", "owner_prefixes": ["notebook-intelligence"]},
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Read-only LiteLLM IOC scanner for macOS and Windows.",
    )
    parser.add_argument(
        "--affected-projects-file",
        help="Optional JSON file that defines known affected project rules.",
    )
    parser.add_argument(
        "--scan-root",
        action="append",
        default=[],
        help="Additional project root to inspect for venv markers and dependency files. Repeatable.",
    )
    parser.add_argument(
        "--docker",
        action="store_true",
        help="Best-effort Docker metadata scan. Reads docker ps/images/inspect if Docker is available.",
    )
    parser.add_argument(
        "--quick",
        action="store_true",
        help="Skip history, log, and cache scans for a faster pass.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit JSON instead of the human-readable report.",
    )
    parser.add_argument(
        "--report-file",
        help="Optional report output path. Uses .json for JSON, .md/.markdown for Markdown, anything else for plain text.",
    )
    parser.add_argument(
        "--report-dir",
        help="Optional directory path. Writes json, markdown, and text reports together.",
    )
    return parser.parse_args()


def normalize_platform() -> str:
    if sys.platform == "darwin":
        return "macos"
    if os.name == "nt":
        return "windows"
    return "other"


def existing_paths(paths: Iterable[Path]) -> List[Path]:
    unique: List[Path] = []
    seen: Set[str] = set()
    for path in paths:
        if not path:
            continue
        path_str = str(path)
        if path_str in seen or not path.exists():
            continue
        seen.add(path_str)
        unique.append(path)
    return unique


def safe_read_text(path: Path, max_bytes: int = MAX_TEXT_BYTES) -> Optional[str]:
    try:
        if path.stat().st_size > max_bytes:
            return None
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def default_affected_projects_file() -> Path:
    return Path(__file__).resolve().with_name("known_affected_projects.json")


def normalize_string_list(values: Any) -> Tuple[str, ...]:
    if not isinstance(values, list):
        return ()
    normalized: List[str] = []
    for value in values:
        if isinstance(value, str) and value.strip():
            normalized.append(value.strip().lower())
    return tuple(normalized)


def normalize_path_list(values: Any, base_dir: Path) -> Tuple[str, ...]:
    if not isinstance(values, list):
        return ()
    normalized: List[str] = []
    for value in values:
        if not isinstance(value, str) or not value.strip():
            continue
        path = Path(value.strip()).expanduser()
        if not path.is_absolute():
            path = (base_dir / path).resolve()
        else:
            path = path.resolve()
        normalized.append(str(path))
    return tuple(normalized)


def build_affected_project_rule(raw_rule: Dict[str, Any]) -> Optional[AffectedProjectRule]:
    label = raw_rule.get("label")
    if not isinstance(label, str) or not label.strip():
        return None
    return AffectedProjectRule(
        label=label.strip(),
        repo_slugs=normalize_string_list(raw_rule.get("repo_slugs", [])),
        dir_names=normalize_string_list(raw_rule.get("dir_names", [])),
        owner_prefixes=normalize_string_list(raw_rule.get("owner_prefixes", [])),
    )


def build_affected_projects_config(raw_payload: Any, source_path: Path, report: ScanReport) -> Optional[AffectedProjectsConfig]:
    if isinstance(raw_payload, dict):
        raw_rules = raw_payload.get("rules", [])
        ignore_paths = normalize_path_list(raw_payload.get("ignore_paths", []), source_path.parent)
        ignore_repo_slugs = normalize_string_list(raw_payload.get("ignore_repo_slugs", []))
        ignore_dir_names = normalize_string_list(raw_payload.get("ignore_dir_names", []))
        ignore_owner_prefixes = normalize_string_list(raw_payload.get("ignore_owner_prefixes", []))
    else:
        raw_rules = raw_payload
        ignore_paths = ()
        ignore_repo_slugs = ()
        ignore_dir_names = ()
        ignore_owner_prefixes = ()

    if not isinstance(raw_rules, list):
        report.add_warning("Affected projects file {} must be a JSON array or an object with a 'rules' array".format(source_path))
        return None

    rules = tuple(
        rule
        for rule in (build_affected_project_rule(item) for item in raw_rules if isinstance(item, dict))
        if rule is not None
    )
    if not rules:
        report.add_warning("Affected projects file {} did not contain any valid rules".format(source_path))
        return None

    return AffectedProjectsConfig(
        rules=rules,
        ignore_paths=ignore_paths,
        ignore_repo_slugs=ignore_repo_slugs,
        ignore_dir_names=ignore_dir_names,
        ignore_owner_prefixes=ignore_owner_prefixes,
    )


def load_affected_projects_config(config_path: Optional[Path], report: ScanReport) -> AffectedProjectsConfig:
    path = config_path or default_affected_projects_file()
    if path.exists():
        text = safe_read_text(path, max_bytes=512 * 1024)
        if text:
            try:
                payload = json.loads(text)
            except json.JSONDecodeError as exc:
                report.add_warning("Could not parse affected projects file {}: {}".format(path, exc))
            else:
                config = build_affected_projects_config(payload, path, report)
                if config is not None:
                    report.remember_path(path)
                    return config
        else:
            report.add_warning("Could not read affected projects file {}".format(path))

    fallback_rules = tuple(
        rule
        for rule in (build_affected_project_rule(item) for item in DEFAULT_AFFECTED_PROJECT_RULES)
        if rule is not None
    )
    return AffectedProjectsConfig(rules=fallback_rules)


def resolve_git_config(project_root: Path) -> Optional[Path]:
    git_path = project_root / ".git"
    if git_path.is_dir():
        config_path = git_path / "config"
        return config_path if config_path.exists() else None
    if not git_path.is_file():
        return None
    text = safe_read_text(git_path, max_bytes=8 * 1024)
    if not text:
        return None
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped.lower().startswith("gitdir:"):
            continue
        git_dir = stripped.split(":", 1)[1].strip()
        git_dir_path = Path(git_dir)
        if not git_dir_path.is_absolute():
            git_dir_path = (project_root / git_dir_path).resolve()
        config_path = git_dir_path / "config"
        return config_path if config_path.exists() else None
    return None


def remote_slugs_for_project(project_root: Path) -> Set[str]:
    config_path = resolve_git_config(project_root)
    if not config_path:
        return set()
    text = safe_read_text(config_path, max_bytes=256 * 1024)
    if not text:
        return set()
    slugs: Set[str] = set()
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped.lower().startswith("url ="):
            continue
        url = stripped.split("=", 1)[1].strip()
        match = GITHUB_REMOTE_RE.search(url)
        if match:
            slugs.add(match.group("slug").lower())
    return slugs


def walk_limited(root: Path, max_depth: int, skip_names: Set[str]) -> Iterable[Tuple[Path, List[str], List[str]]]:
    if not root.exists():
        return
    root = root.resolve()
    for current, dirnames, filenames in os.walk(root):
        current_path = Path(current)
        try:
            depth = len(current_path.relative_to(root).parts)
        except ValueError:
            depth = 0
        dirnames[:] = [name for name in dirnames if name not in skip_names]
        if depth >= max_depth:
            dirnames[:] = []
        yield current_path, dirnames, filenames


def common_dev_roots(home: Path, cwd: Path, extra_roots: Sequence[Path]) -> List[Path]:
    candidates = [cwd]
    for name in DEV_ROOT_NAMES:
        candidates.append(home / name)
    for name in HIDDEN_DEV_ROOT_NAMES:
        candidates.append(home / name)
    if normalize_platform() == "windows":
        documents = home / "Documents"
        candidates.extend(
            [
                documents / "Projects",
                documents / "Code",
                home / "source",
                home / "repos",
                home / ".virtualenvs",
            ]
        )
    candidates.extend(extra_roots)
    return existing_paths(candidates)


def python_root_candidates(home: Path) -> List[Path]:
    platform_name = normalize_platform()
    candidates = [
        home / ".pyenv",
        home / ".conda",
        home / "miniconda3",
        home / "anaconda3",
    ]
    if platform_name == "macos":
        candidates.extend(
            [
                home / "Library" / "Python",
                Path("/Library/Frameworks/Python.framework"),
                Path("/opt/homebrew/lib"),
                Path("/opt/homebrew/Frameworks"),
                Path("/usr/local/lib"),
                Path("/usr/local/Frameworks"),
            ]
        )
    elif platform_name == "windows":
        appdata = Path(os.environ.get("APPDATA", home / "AppData" / "Roaming"))
        local_appdata = Path(os.environ.get("LOCALAPPDATA", home / "AppData" / "Local"))
        candidates.extend(
            [
                appdata / "Python",
                local_appdata / "Programs" / "Python",
                local_appdata / "pypoetry",
                local_appdata / "uv",
            ]
        )
        for env_name in ("ProgramFiles", "ProgramFiles(x86)"):
            base = os.environ.get(env_name)
            if base:
                candidates.append(Path(base))
    return existing_paths(candidates)


def discover_virtual_envs(dev_roots: Sequence[Path]) -> List[Path]:
    found: Set[str] = set()
    envs: List[Path] = []
    for root in dev_roots:
        for current, dirnames, filenames in walk_limited(root, max_depth=6, skip_names=SEARCH_SKIP_NAMES):
            if "pyvenv.cfg" in filenames:
                env_root = current
                env_key = str(env_root)
                if env_key not in found:
                    found.add(env_key)
                    envs.append(env_root)
                dirnames[:] = []
                continue
            conda_history = current / "conda-meta" / "history"
            if conda_history.exists():
                env_key = str(current)
                if env_key not in found:
                    found.add(env_key)
                    envs.append(current)
                dirnames[:] = []
    return envs


def conda_env_candidates(home: Path) -> List[Path]:
    roots = [
        home / ".conda" / "envs",
        home / "miniconda3" / "envs",
        home / "anaconda3" / "envs",
    ]
    if normalize_platform() == "windows":
        local_appdata = Path(os.environ.get("LOCALAPPDATA", home / "AppData" / "Local"))
        roots.extend(
            [
                local_appdata / "miniconda3" / "envs",
                local_appdata / "anaconda3" / "envs",
            ]
        )
    envs: List[Path] = []
    for root in existing_paths(roots):
        try:
            for child in root.iterdir():
                if (child / "conda-meta" / "history").exists():
                    envs.append(child)
        except OSError:
            continue
    return envs


def discover_site_packages_dirs(roots: Sequence[Path]) -> List[Path]:
    site_packages: List[Path] = []
    seen: Set[str] = set()
    for root in existing_paths(roots):
        if root.name in SITE_PACKAGES_DIRS:
            root_key = str(root)
            if root_key not in seen:
                seen.add(root_key)
                site_packages.append(root)
            continue
        for current, dirnames, _ in walk_limited(root, max_depth=8, skip_names=SEARCH_SKIP_NAMES):
            if current.name in SITE_PACKAGES_DIRS:
                current_key = str(current)
                if current_key not in seen:
                    seen.add(current_key)
                    site_packages.append(current)
                dirnames[:] = []
    return site_packages


def metadata_version(metadata_path: Path) -> Optional[str]:
    text = safe_read_text(metadata_path, max_bytes=256 * 1024)
    if not text:
        return None
    for line in text.splitlines():
        if line.startswith("Version: "):
            return line.split(": ", 1)[1].strip()
    return None


def scan_site_packages(site_packages: Path, report: ScanReport) -> None:
    report.remember_path(site_packages)
    report.counts["site_packages_dirs"] += 1

    pth_path = site_packages / "litellm_init.pth"
    if pth_path.exists():
        text = safe_read_text(pth_path, max_bytes=64 * 1024) or ""
        detail = "Found litellm_init.pth"
        if "import " in text:
            detail += " with executable import code"
        report.add_finding("critical", "pth_ioc", pth_path, detail)

    litellm_dir = site_packages / "litellm"
    if litellm_dir.is_dir():
        report.add_finding("info", "package_present", litellm_dir, "LiteLLM package directory exists")
        proxy_path = litellm_dir / "proxy" / "proxy_server.py"
        proxy_text = safe_read_text(proxy_path)
        if proxy_text and PROXY_IOC_RE.search(proxy_text):
            report.add_finding("critical", "proxy_ioc", proxy_path, "Known IOC pattern found in proxy_server.py")

    try:
        children = list(site_packages.iterdir())
    except OSError:
        report.add_warning("Could not list {}".format(site_packages))
        return

    for child in children:
        match = DIST_INFO_RE.match(child.name)
        if not match:
            continue
        version = match.group(1)
        metadata_path = child / "METADATA"
        metadata_version_value = metadata_version(metadata_path)
        if metadata_version_value:
            version = metadata_version_value
        detail = "Installed LiteLLM version {}".format(version)
        severity = "critical" if version in IMPACTED_VERSIONS else "info"
        category = "installed_impacted_version" if severity == "critical" else "installed_version"
        report.add_finding(severity, category, child, detail)


def dependency_roots(home: Path, cwd: Path, extra_roots: Sequence[Path]) -> List[Path]:
    return common_dev_roots(home, cwd, extra_roots)


def extract_versions(text: str) -> List[str]:
    return sorted(set(GENERIC_VERSION_RE.findall(text)))


def discover_project_roots(roots: Sequence[Path]) -> List[Path]:
    seen: Set[str] = set()
    project_roots: List[Path] = []
    for root in roots:
        for current, dirnames, filenames in walk_limited(root, max_depth=5, skip_names=DEPENDENCY_SKIP_NAMES):
            is_project_root = (current / ".git").exists() or any(filename in DEPENDENCY_FILE_NAMES for filename in filenames)
            if not is_project_root:
                continue
            current_key = str(current)
            if current_key in seen:
                continue
            seen.add(current_key)
            project_roots.append(current)
            dirnames[:] = [name for name in dirnames if name != ".git"]
    return project_roots


def should_ignore_project(
    project_root: Path,
    remote_slugs: Set[str],
    affected_projects_config: AffectedProjectsConfig,
) -> bool:
    root_name = project_root.name.lower()
    try:
        resolved_root = project_root.resolve()
    except OSError:
        resolved_root = project_root

    for ignored_path_str in affected_projects_config.ignore_paths:
        ignored_path = Path(ignored_path_str)
        if resolved_root == ignored_path:
            return True
        try:
            resolved_root.relative_to(ignored_path)
            return True
        except ValueError:
            pass

    if root_name in affected_projects_config.ignore_dir_names:
        return True
    if any(remote_slug in affected_projects_config.ignore_repo_slugs for remote_slug in remote_slugs):
        return True
    if any(
        remote_slug.startswith(owner_prefix + "/")
        for owner_prefix in affected_projects_config.ignore_owner_prefixes
        for remote_slug in remote_slugs
    ):
        return True
    return False


def match_affected_project(
    project_root: Path,
    affected_projects_config: AffectedProjectsConfig,
) -> Optional[Tuple[str, str]]:
    root_name = project_root.name.lower()
    remote_slugs = remote_slugs_for_project(project_root)
    if should_ignore_project(project_root, remote_slugs, affected_projects_config):
        return None

    for rule in affected_projects_config.rules:
        if remote_slugs and any(remote_slug == repo_slug for repo_slug in rule.repo_slugs for remote_slug in remote_slugs):
            return (
                "medium",
                "Local repository matches known affected project {}; review whether dependencies were installed during the impacted LiteLLM window.".format(
                    rule.label
                ),
            )
        if remote_slugs and any(remote_slug.startswith(owner_prefix + "/") for owner_prefix in rule.owner_prefixes for remote_slug in remote_slugs):
            return (
                "medium",
                "Local repository owner matches truncated known affected project entry {} from the user-supplied list.".format(
                    rule.label
                ),
            )
        if rule.dir_names and root_name in rule.dir_names:
            return (
                "info",
                "Project directory name matches known affected project {}.".format(rule.label),
            )
    return None


def scan_known_affected_projects(
    roots: Sequence[Path],
    affected_projects_config: AffectedProjectsConfig,
    report: ScanReport,
) -> None:
    for project_root in discover_project_roots(roots):
        report.counts["project_roots"] += 1
        report.remember_path(project_root)
        match = match_affected_project(project_root, affected_projects_config)
        if not match:
            continue
        severity, detail = match
        report.add_finding(severity, "known_affected_project", project_root, detail)


def scan_dependency_files(roots: Sequence[Path], report: ScanReport) -> None:
    for root in roots:
        for current, dirnames, filenames in walk_limited(root, max_depth=5, skip_names=DEPENDENCY_SKIP_NAMES):
            for filename in filenames:
                if filename not in DEPENDENCY_FILE_NAMES:
                    continue
                path = current / filename
                report.remember_path(path)
                report.counts["dependency_files"] += 1
                text = safe_read_text(path)
                if not text or not LITELLM_RE.search(text):
                    continue
                severity = "medium"
                detail = "Dependency file references LiteLLM"
                if LITELLM_IMPACTED_RE.search(text):
                    detail = "Dependency file references impacted LiteLLM version 1.82.7 or 1.82.8"
                else:
                    severity = "info"
                    versions = extract_versions(text)
                    if versions:
                        detail = "Dependency file references LiteLLM; nearby versions seen: {}".format(", ".join(versions[:5]))
                report.add_finding(severity, "dependency_reference", path, detail)


def cache_roots(home: Path) -> List[Path]:
    platform_name = normalize_platform()
    roots = [
        home / ".cache" / "uv",
        home / ".cache" / "pip",
        home / "Downloads",
    ]
    if platform_name == "macos":
        roots.extend(
            [
                home / "Library" / "Caches" / "uv",
                home / "Library" / "Caches" / "pip",
                home / ".pkg-cache",
            ]
        )
    elif platform_name == "windows":
        local_appdata = Path(os.environ.get("LOCALAPPDATA", home / "AppData" / "Local"))
        roots.extend(
            [
                local_appdata / "uv" / "cache",
                local_appdata / "pip" / "Cache",
            ]
        )
    return existing_paths(roots)


def scan_caches(roots: Sequence[Path], report: ScanReport) -> None:
    seen_versions: Dict[str, Set[str]] = {}
    for root in roots:
        for current, dirnames, filenames in walk_limited(root, max_depth=6, skip_names=SEARCH_SKIP_NAMES):
            report.remember_path(current)
            hits: Set[str] = set()
            if current.name.lower() == "litellm":
                hits.update(extract_versions(str(current)))
            for name in list(dirnames) + list(filenames):
                lowered = name.lower()
                if "litellm" in lowered:
                    hits.update(extract_versions(name))
            if not hits:
                continue
            root_key = str(root)
            seen_versions.setdefault(root_key, set()).update(hits)

    for root_str, versions in sorted(seen_versions.items()):
        impacted = sorted(version for version in versions if version in IMPACTED_VERSIONS)
        if impacted:
            report.add_finding(
                "medium",
                "cache_artifact",
                Path(root_str),
                "Cache contains impacted LiteLLM versions: {}".format(", ".join(impacted)),
            )
            continue
        report.add_finding(
            "info",
            "cache_artifact",
            Path(root_str),
            "Cache contains LiteLLM artifacts; versions seen: {}".format(", ".join(sorted(versions)[:10])),
        )


def history_files(home: Path) -> List[Path]:
    files = [
        home / ".zsh_history",
        home / ".bash_history",
    ]
    if normalize_platform() == "windows":
        appdata = Path(os.environ.get("APPDATA", home / "AppData" / "Roaming"))
        files.append(appdata / "Microsoft" / "Windows" / "PowerShell" / "PSReadLine" / "ConsoleHost_history.txt")
    return existing_paths(files)


def scan_history(files: Sequence[Path], report: ScanReport) -> None:
    for path in files:
        report.counts["history_files"] += 1
        report.remember_path(path)
        text = safe_read_text(path)
        if not text or not LITELLM_RE.search(text):
            continue
        severity = "medium" if LITELLM_IMPACTED_RE.search(text) else "info"
        detail = "Shell history mentions LiteLLM"
        if severity == "medium":
            detail = "Shell history mentions impacted LiteLLM version 1.82.7 or 1.82.8"
        report.add_finding(severity, "history_reference", path, detail)


def log_roots(home: Path) -> List[Path]:
    platform_name = normalize_platform()
    roots = [
        home / ".docker",
        home / ".cursor",
        home / ".gemini",
        home / ".codex",
        home / ".openwork",
    ]
    if platform_name == "macos":
        roots.append(home / "Library" / "Logs")
    elif platform_name == "windows":
        local_appdata = Path(os.environ.get("LOCALAPPDATA", home / "AppData" / "Local"))
        appdata = Path(os.environ.get("APPDATA", home / "AppData" / "Roaming"))
        roots.extend(
            [
                local_appdata / "Docker",
                local_appdata / "Cursor",
                appdata / "Cursor",
            ]
        )
    return existing_paths(roots)


def is_text_candidate(path: Path) -> bool:
    if path.suffix.lower() in TEXT_FILE_SUFFIXES:
        return True
    return path.suffix == "" and path.name.lower() in {"history", "config", "settings"}


def scan_logs(roots: Sequence[Path], report: ScanReport) -> None:
    for root in roots:
        for current, dirnames, filenames in walk_limited(root, max_depth=5, skip_names=SEARCH_SKIP_NAMES):
            for filename in filenames:
                path = current / filename
                if not is_text_candidate(path):
                    continue
                report.counts["log_files"] += 1
                text = safe_read_text(path)
                if not text or IOC_DOMAIN not in text:
                    continue
                report.add_finding("critical", "domain_ioc", path, "Known IOC domain found in a log or config file")


def run_command(command: Sequence[str]) -> Tuple[int, str, str]:
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
    except OSError as exc:
        return 1, "", str(exc)
    return completed.returncode, completed.stdout, completed.stderr


def scan_docker(report: ScanReport) -> None:
    docker_path = shutil.which("docker")
    if not docker_path:
        report.add_warning("Docker CLI not found; skipped Docker scan")
        return

    exit_code, containers_out, containers_err = run_command(
        [docker_path, "ps", "-a", "--format", "{{.ID}} {{.Image}} {{.State}} {{.Names}}"]
    )
    if exit_code != 0:
        report.add_warning("Docker metadata scan failed: {}".format(containers_err.strip() or "docker ps error"))
        return

    container_ids: List[str] = []
    for line in containers_out.splitlines():
        line = line.strip()
        if not line:
            continue
        report.counts["docker_objects"] += 1
        parts = line.split(None, 3)
        if parts:
            container_ids.append(parts[0])
        lowered = line.lower()
        if "litellm" in lowered:
            report.add_finding("medium", "docker_reference", Path("docker://container"), "Container metadata mentions LiteLLM: {}".format(line))

    exit_code, images_out, images_err = run_command(
        [docker_path, "images", "--format", "{{.Repository}}:{{.Tag}} {{.ID}}"]
    )
    if exit_code != 0:
        report.add_warning("Docker image scan failed: {}".format(images_err.strip() or "docker images error"))
        return

    image_ids: List[str] = []
    for line in images_out.splitlines():
        line = line.strip()
        if not line:
            continue
        report.counts["docker_objects"] += 1
        parts = line.rsplit(" ", 1)
        if len(parts) == 2:
            image_ids.append(parts[1])
        if "litellm" in line.lower():
            report.add_finding("medium", "docker_reference", Path("docker://image"), "Image metadata mentions LiteLLM: {}".format(line))

    inspect_targets = container_ids + image_ids
    if not inspect_targets:
        return

    exit_code, inspect_out, inspect_err = run_command([docker_path, "inspect"] + inspect_targets)
    if exit_code != 0:
        report.add_warning("Docker inspect failed: {}".format(inspect_err.strip() or "docker inspect error"))
        return

    if IOC_DOMAIN in inspect_out:
        report.add_finding("critical", "docker_ioc", Path("docker://inspect"), "Docker inspect output contains known IOC domain")
    elif LITELLM_IMPACTED_RE.search(inspect_out):
        report.add_finding("medium", "docker_ioc", Path("docker://inspect"), "Docker inspect output references impacted LiteLLM versions")
    elif LITELLM_RE.search(inspect_out):
        report.add_finding("info", "docker_reference", Path("docker://inspect"), "Docker inspect output references LiteLLM")


def report_to_json(report: ScanReport) -> str:
    payload = {
        "platform": report.platform,
        "home": report.home,
        "hostname": report.hostname,
        "generated_at_utc": report.generated_at_utc,
        "extra_scan_roots": report.extra_scan_roots,
        "counts": report.counts,
        "warnings": report.warnings,
        "scanned_paths": sorted(report.scanned_paths),
        "findings": [asdict(finding) for finding in report.findings],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)


def report_to_markdown(report: ScanReport) -> str:
    findings_by_severity: Dict[str, List[Finding]] = {"critical": [], "medium": [], "info": []}
    for finding in report.findings:
        findings_by_severity.setdefault(finding.severity, []).append(finding)

    lines = [
        "# LiteLLM IOC Scan",
        "",
        "## Summary",
        "",
        "- Platform: `{}`".format(report.platform),
        "- Home: `{}`".format(report.home),
        "- Hostname: `{}`".format(report.hostname),
        "- Generated at (UTC): `{}`".format(report.generated_at_utc),
        "- Environment roots: `{}`".format(report.counts["environment_roots"]),
        "- Project roots: `{}`".format(report.counts["project_roots"]),
        "- Site-packages dirs: `{}`".format(report.counts["site_packages_dirs"]),
        "- Dependency files: `{}`".format(report.counts["dependency_files"]),
        "- History files: `{}`".format(report.counts["history_files"]),
        "- Log files: `{}`".format(report.counts["log_files"]),
        "- Docker objects: `{}`".format(report.counts["docker_objects"]),
        "",
    ]

    for severity in ("critical", "medium", "info"):
        items = findings_by_severity.get(severity, [])
        lines.append("## {} Findings ({})".format(severity.capitalize(), len(items)))
        lines.append("")
        if not items:
            lines.append("- None")
            lines.append("")
            continue
        for finding in items:
            lines.append("- `{}` [{}] {}".format(finding.path, finding.category, finding.detail))
        lines.append("")

    if report.warnings:
        lines.append("## Warnings")
        lines.append("")
        for warning in report.warnings:
            lines.append("- {}".format(warning))
        lines.append("")

    lines.extend(
        [
            "## Interpretation",
            "",
            "- `critical`: known IOC or impacted installed version",
            "- `medium`: suspicious historical evidence that needs review",
            "- `info`: LiteLLM was present, but no known IOC matched",
        ]
    )
    return "\n".join(lines)


def summarize(report: ScanReport) -> str:
    findings_by_severity: Dict[str, List[Finding]] = {"critical": [], "medium": [], "info": []}
    for finding in report.findings:
        findings_by_severity.setdefault(finding.severity, []).append(finding)

    lines = [
        "LiteLLM IOC Scan",
        "Platform: {}".format(report.platform),
        "Home: {}".format(report.home),
        "Hostname: {}".format(report.hostname),
        "Generated at (UTC): {}".format(report.generated_at_utc),
        "",
        "Counts:",
        "  environment roots: {}".format(report.counts["environment_roots"]),
        "  project roots: {}".format(report.counts["project_roots"]),
        "  site-packages dirs: {}".format(report.counts["site_packages_dirs"]),
        "  dependency files: {}".format(report.counts["dependency_files"]),
        "  history files: {}".format(report.counts["history_files"]),
        "  log files: {}".format(report.counts["log_files"]),
        "  docker objects: {}".format(report.counts["docker_objects"]),
        "",
    ]

    for severity in ("critical", "medium", "info"):
        items = findings_by_severity.get(severity, [])
        lines.append("{} findings: {}".format(severity.upper(), len(items)))
        for finding in items[:20]:
            lines.append("  - [{}] {} :: {}".format(finding.category, finding.path, finding.detail))
        if len(items) > 20:
            lines.append("  - ... {} more".format(len(items) - 20))
        lines.append("")

    if report.warnings:
        lines.append("Warnings:")
        for warning in report.warnings:
            lines.append("  - {}".format(warning))
        lines.append("")

    if not report.findings:
        lines.append("No LiteLLM IOC findings were detected in the scanned paths.")
    else:
        lines.append("Interpretation:")
        lines.append("  - critical: known IOC or impacted installed version")
        lines.append("  - medium: suspicious historical evidence that needs review")
        lines.append("  - info: LiteLLM was present, but no known IOC matched")
    return "\n".join(lines)


def exit_code_for(report: ScanReport) -> int:
    severities = {finding.severity for finding in report.findings}
    if "critical" in severities:
        return 2
    if "medium" in severities:
        return 1
    return 0


def report_format_for_path(path: Path) -> str:
    suffix = path.suffix.lower()
    if suffix == ".json":
        return "json"
    if suffix in {".md", ".markdown"}:
        return "markdown"
    return "text"


def render_report_for_file(report: ScanReport, path: Path) -> str:
    report_format = report_format_for_path(path)
    if report_format == "json":
        return report_to_json(report)
    if report_format == "markdown":
        return report_to_markdown(report)
    return summarize(report)


def write_report_file(report: ScanReport, path: Path) -> None:
    content = render_report_for_file(report, path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content + ("\n" if not content.endswith("\n") else ""), encoding="utf-8")


def write_report_bundle(report: ScanReport, directory: Path) -> List[Path]:
    directory.mkdir(parents=True, exist_ok=True)
    outputs = [
        directory / "findlitellm-report.json",
        directory / "findlitellm-report.md",
        directory / "findlitellm-report.txt",
    ]
    for output_path in outputs:
        write_report_file(report, output_path)
    return outputs


def main() -> int:
    args = parse_args()
    home = Path.home()
    cwd = Path.cwd()
    extra_roots = [Path(path).expanduser() for path in args.scan_root]
    report = ScanReport(
        platform=normalize_platform(),
        home=str(home),
        hostname=socket.gethostname(),
        generated_at_utc=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        extra_scan_roots=[str(path) for path in extra_roots],
    )
    affected_projects_file = Path(args.affected_projects_file).expanduser() if args.affected_projects_file else None
    affected_projects_config = load_affected_projects_config(affected_projects_file, report)

    dev_roots = common_dev_roots(home, cwd, extra_roots)
    python_roots = python_root_candidates(home)
    env_roots = existing_paths(discover_virtual_envs(dev_roots) + conda_env_candidates(home) + python_roots)
    report.counts["environment_roots"] = len(env_roots)
    for root in env_roots:
        report.remember_path(root)

    scan_known_affected_projects(dependency_roots(home, cwd, extra_roots), affected_projects_config, report)
    site_packages_dirs = discover_site_packages_dirs(env_roots)
    for site_packages in site_packages_dirs:
        scan_site_packages(site_packages, report)

    scan_dependency_files(dependency_roots(home, cwd, extra_roots), report)

    if not args.quick:
        scan_caches(cache_roots(home), report)
        scan_history(history_files(home), report)
        scan_logs(log_roots(home), report)

    if args.docker:
        scan_docker(report)

    output = report_to_json(report) if args.json else summarize(report)
    sys.stdout.write(output)
    sys.stdout.write("\n")
    if args.report_file:
        report_path = Path(args.report_file).expanduser()
        write_report_file(report, report_path)
    if args.report_dir:
        report_dir = Path(args.report_dir).expanduser()
        write_report_bundle(report, report_dir)
    return exit_code_for(report)


if __name__ == "__main__":
    raise SystemExit(main())
