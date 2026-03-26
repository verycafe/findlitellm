# findlitellm

[English README](README.md)

`findlitellm` 是一个面向 macOS 和 Windows 的 LiteLLM IOC 只读排查工具，主要用来快速检查：

- 已安装的 LiteLLM 包及已知受影响版本
- `litellm_init.pth`
- `proxy_server.py` 中的已知 IOC 模式
- 依赖文件、缓存、shell 历史和日志中的 LiteLLM 痕迹
- 本机是否存在命中“已知受影响项目”的仓库

工具只依赖 Python 标准库。

## 仓库结构

- `findlitellm.py`：主扫描脚本
- `known_affected_projects.json`：可配置的已知受影响项目列表
- `run_macos.command`：macOS 双击启动入口
- `run_windows.bat`：Windows 双击启动入口

## 快速开始

macOS：

```bash
python3 findlitellm.py
python3 findlitellm.py --quick
python3 findlitellm.py --docker
```

Windows：

```bat
py -3 findlitellm.py
py -3 findlitellm.py --quick
py -3 findlitellm.py --docker
```

## 常用参数

- `--scan-root /path/to/project`：补充要扫描的项目根目录
- `--quick`：跳过缓存、历史和日志扫描
- `--docker`：如果本机可用 Docker，则额外检查 Docker 元数据
- `--json`：标准输出改为 JSON
- `--report-file /path/to/report.json`：输出单个报告文件
- `--report-dir /path/to/reports`：一次输出 `json`、`md`、`txt` 三份报告
- `--affected-projects-file /path/to/custom.json`：使用自定义已知受影响项目配置

## 报告输出

`--report-file` 会根据扩展名自动决定格式：

- `.json`：结构化 JSON
- `.md` 或 `.markdown`：Markdown
- 其他扩展名：纯文本摘要

`--report-dir` 会生成：

- `findlitellm-report.json`
- `findlitellm-report.md`
- `findlitellm-report.txt`

所有报告都会包含：

- `hostname`
- `generated_at_utc`

## 严重级别

- `critical`：命中已知 IOC，或任何位置检测到 LiteLLM `1.82.7` / `1.82.8`
- `medium`：存在可疑历史痕迹，建议继续复核
- `info`：发现过 LiteLLM，但没有命中已知 IOC

也就是说，现在不仅“已安装受影响版本”会升为 `critical`，只要在依赖文件、缓存、shell 历史或 Docker 元数据里发现 `1.82.7` / `1.82.8`，也会直接按报警级别处理。

退出码：

- `0`：没有 `critical` 或 `medium`
- `1`：存在一个或多个 `medium`
- `2`：存在一个或多个 `critical`

## 已知受影响项目配置

默认会读取脚本同目录下的 `known_affected_projects.json`。

支持的顶层字段有：

- `rules`
- `ignore_paths`
- `ignore_repo_slugs`
- `ignore_dir_names`
- `ignore_owner_prefixes`

示例：

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

## 边界说明

- Docker 扫描是 best-effort，是否能跑取决于本机 Docker 访问权限。
- Windows 路径发现是启发式扫描，无法覆盖所有自定义盘符布局。
- 这是只读工具，不会卸载包，也不会替你轮换密钥。
