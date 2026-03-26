# findlitellm

[中文说明](README.zh-CN.md)

`findlitellm` is a read-only LiteLLM IOC scanner for macOS and Windows. It helps you quickly check:

- installed LiteLLM packages and known impacted versions
- `litellm_init.pth`
- known IOC patterns in `proxy_server.py`
- LiteLLM references in dependency files, caches, shell history, and logs
- local repositories that match known affected projects

The tool uses only the Python standard library.

## Repository Layout

- `findlitellm.py`: main scanner
- `known_affected_projects.json`: configurable list of known affected projects
- `run_macos.command`: double-click launcher for macOS
- `run_windows.bat`: double-click launcher for Windows

## Quick Start

macOS:

```bash
python3 findlitellm.py
python3 findlitellm.py --quick
python3 findlitellm.py --docker
```

Windows:

```bat
py -3 findlitellm.py
py -3 findlitellm.py --quick
py -3 findlitellm.py --docker
```

## Useful Options

- `--scan-root /path/to/project`: add extra project roots to inspect
- `--quick`: skip cache, history, and log scans
- `--docker`: inspect Docker metadata if Docker is available
- `--json`: print JSON to stdout instead of the text summary
- `--report-file /path/to/report.json`: write one report file
- `--report-dir /path/to/reports`: write `json`, `md`, and `txt` reports together
- `--affected-projects-file /path/to/custom.json`: use a custom known-affected-projects config

## Reports

`--report-file` chooses the format from the file extension:

- `.json`: structured JSON
- `.md` or `.markdown`: Markdown
- any other extension: plain text summary

`--report-dir` creates:

- `findlitellm-report.json`
- `findlitellm-report.md`
- `findlitellm-report.txt`

All report formats include:

- `hostname`
- `generated_at_utc`

## Severity Levels

- `critical`: known IOC or impacted installed version
- `medium`: suspicious historical evidence that should be reviewed
- `info`: LiteLLM was present, but no known IOC matched

Exit codes:

- `0`: no `critical` or `medium` findings
- `1`: one or more `medium` findings
- `2`: one or more `critical` findings

## Known Affected Projects Config

By default the scanner reads `known_affected_projects.json` from the same directory as the script.

Supported top-level fields:

- `rules`
- `ignore_paths`
- `ignore_repo_slugs`
- `ignore_dir_names`
- `ignore_owner_prefixes`

Example:

```json
{
  "rules": [
    {
      "label": "stanfordnlp/dspy",
      "repo_slugs": ["stanfordnlp/dspy"],
      "dir_names": ["dspy"]
    }
  ],
  "ignore_paths": ["/Users/you/Projects/dspy-fork"],
  "ignore_repo_slugs": ["your-org/dspy-internal"],
  "ignore_dir_names": ["scratch-dspy"],
  "ignore_owner_prefixes": ["your-org"]
}
```

## Limitations

- Docker scanning is best-effort and depends on local Docker access.
- Windows path discovery is heuristic and cannot cover every custom drive layout.
- The tool is read-only. It does not uninstall packages or rotate credentials.
