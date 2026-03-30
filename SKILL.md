---
name: sarif-postprocess
description: Use when SARIF findings need source-aware security reporting with source and sink locations, call-flow evidence, code snippets, and remediation guidance. 当 SARIF 结果需要结合源码位置、source/sink、调用链证据、代码片段与修复建议生成更可操作的安全报告时使用。
---

# SARIF Postprocess Skill
# SARIF 后处理技能

Treat SARIF as the finding index, then enrich it with source code or a CodeQL database source archive so the final report explains where the issue starts, where it lands, and how to fix it.
将 SARIF 视为漏洞索引，再结合源码或 CodeQL 数据库中的源码归档进行增强，使最终报告能够说明漏洞从哪里开始、落到哪里，以及应该如何修复。

## When To Use
## 适用场景

- SARIF tells you a rule fired, but the report still does not explain the vulnerable code path.
- SARIF 只告诉你某条规则命中了，但报告仍然无法解释真实的漏洞代码路径。

- You need a report that answers where the source is, where the sink is, what the path looks like, and what should be changed.
- 你需要一份能回答 source 在哪里、sink 在哪里、链路长什么样、代码应该怎么改的报告。

- You have one SARIF file, many SARIF files, or a CodeQL output directory and want one triage-ready report.
- 你有单个 SARIF、多个 SARIF，或者整个 CodeQL 输出目录，并希望得到一份可直接用于分诊的报告。

- You have a source checkout or a CodeQL database and want line-level code evidence in the report.
- 你拥有源码 checkout 或 CodeQL database，并希望报告里带有行级别的代码证据。

## Inputs
## 输入

Accept a single SARIF file or a directory containing SARIF files.
接受单个 SARIF 文件，或包含多个 SARIF 文件的目录。

Optional enrichment inputs are `source-root` and `codeql-db`.
可选的增强输入包括 `source-root` 和 `codeql-db`。

Use `source-root` to load source snippets from a repository checkout.
使用 `source-root` 从源码仓库 checkout 中读取代码片段。

Use `codeql-db` as a fallback source archive provider when it contains `src.zip`.
当 `codeql-db` 中包含 `src.zip` 时，可将其作为源码片段的回退来源。

Prefer explicit metadata such as repository path, commit or tag, scan time, and language when available.
如果可以，优先提供仓库路径、commit 或 tag、扫描时间和语言等显式元数据。

## Output Contract
## 输出约定

Always generate `normalized.json`, `summary.json`, and `report.md`.
始终生成 `normalized.json`、`summary.json` 和 `report.md`。

Optionally generate `llm_analysis.json` and `fix_plan.md` when the user asks for them.
当用户明确要求时，可额外生成 `llm_analysis.json` 和 `fix_plan.md`。

## Workflow
## 工作流

1. Validate the SARIF payload before any transformation.
1. 在做任何转换之前先验证 SARIF 载荷。

Require at least `runs[0]` and fail fast on malformed input.
要求至少存在 `runs[0]`，如果输入格式异常则快速失败。

2. Normalize each finding into a stable schema.
2. 将每条 finding 归一化为稳定的数据结构。

Extract rule id, rule name, message, severity, security severity, primary location, tags, taxonomies, related locations, and SARIF code-flow steps.
提取规则 ID、规则名称、消息、严重性、安全严重性、主位置、标签、分类信息、相关位置以及 SARIF 的代码流步骤。

3. Deduplicate deterministically.
3. 使用确定性规则去重。

Use `(rule_id, file, line, compact_message)` as the fingerprint basis.
使用 `(rule_id, file, line, compact_message)` 作为指纹基础字段。

4. Enrich with source evidence.
4. 用源码证据增强 finding。

Prefer `source-root` for snippets, and fall back to `codeql-db/src.zip` when the checkout is missing or incomplete.
优先从 `source-root` 读取代码片段；如果本地 checkout 缺失或不完整，则回退到 `codeql-db/src.zip`。

5. Summarize the source-to-sink path.
5. 汇总从 source 到 sink 的路径。

For every finding, derive source location, sink location, step count, and touched files.
对每条 finding 计算 source 位置、sink 位置、步骤数以及涉及的文件。

6. Render a detailed security report.
6. 生成详细的安全报告。

The report must answer where tainted data enters, where it reaches the dangerous sink, what evidence exists, which code lines matter, and what remediation pattern fits the issue.
报告必须回答污点数据从哪里进入、到达了哪个危险 sink、有哪些证据、哪些代码行最关键，以及该漏洞适合哪类修复模式。

7. Be explicit about limits.
7. 明确说明能力边界和限制。

If source snippets are unavailable, say the report is SARIF-only.
如果源码片段不可用，就明确说明该报告只能基于 SARIF。

If a CodeQL database is present but the local `codeql` CLI is unavailable, do not claim database query expansion happened.
如果存在 CodeQL database 但本地没有 `codeql` CLI，不要声称已经进行了数据库级查询增强。

## Scripts
## 脚本

Use bundled scripts before writing ad-hoc code.
优先使用内置脚本，不要先写一次性代码。

- `scripts/normalize_sarif.py`
- `scripts/normalize_sarif.py`

- `scripts/render_report.py`
- `scripts/render_report.py`

Patch these scripts first when functionality is missing.
当功能不足时，优先修改这两个脚本。

## Commands
## 命令示例

Single SARIF plus source checkout:
单个 SARIF 配合源码 checkout：

```bash
python scripts/normalize_sarif.py \
  --input path/to/result.sarif \
  --out out/normalized.json \
  --source-root /path/to/repo

python scripts/render_report.py \
  --input out/normalized.json \
  --out-dir out
```

Directory of SARIF files with CodeQL DB fallback:
多个 SARIF 文件目录并带 CodeQL DB 回退：

```bash
python scripts/normalize_sarif.py \
  --input path/to/codeql-out \
  --out out/normalized.json \
  --source-root /path/to/repo \
  --codeql-db /path/to/codeql-db/brpc-cpp

python scripts/render_report.py \
  --input out/normalized.json \
  --out-dir out \
  --top 20
```

## Quality Gates
## 质量门禁

- Raw count, normalized count, and duplicates removed must reconcile.
- 原始数量、归一化数量和去重数量必须彼此一致。

- Every finding must contain `rule_id` plus a primary location or explicit `unknown`.
- 每条 finding 都必须包含 `rule_id`，以及主位置或显式的 `unknown` 标记。

- `summary.json` risk bucket totals must equal the total finding count.
- `summary.json` 中各风险分桶的总和必须等于 finding 总数。

- `report.md` must include primary location, source and sink, call flow, vulnerability mechanism, and remediation guidance.
- `report.md` 必须包含主位置、source 与 sink、调用链、漏洞机理和修复建议。

- If source context is unavailable, the report must say so instead of implying that line-level review happened.
- 如果源码上下文不可用，报告必须明确说明，而不是暗示已经做了行级代码审查。

## Safety Boundaries
## 安全边界

- Do not execute code from SARIF snippets.
- 不要执行 SARIF 片段中的任何代码。

- Do not claim exploitability certainty without direct evidence.
- 没有直接证据时，不要声称漏洞一定可利用。

- Do not claim CodeQL DB query expansion unless you actually queried it.
- 除非你真的查询过 CodeQL DB，否则不要声称已经做了数据库增强分析。

- Keep raw SARIF separate from derived artifacts.
- 原始 SARIF 与衍生产物必须分离保存。

## References
## 参考资料

Load only when needed.
仅在需要时加载。

- `references/schema.md`
- `references/schema.md`

- `references/risk-mapping.md`
- `references/risk-mapping.md`

- `references/prompt-contract.md`
- `references/prompt-contract.md`
