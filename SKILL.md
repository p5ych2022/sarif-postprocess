---
name: sarif-postprocess
description: Use when SARIF findings need source-aware security reporting with source and sink locations, call-flow evidence, code snippets, or remediation guidance.|当 SARIF 告警需要结合源码生成安全报告，并补充 source / sink 位置、调用流证据、代码片段或修复建议时使用。
---

# SARIF Postprocess Skill|SARIF 后处理技能

## Overview|概览

Treat SARIF as the finding index, then enrich it with repository source code or a CodeQL database source archive so the final report explains where the issue starts, where it lands, and how it should be fixed. 把 SARIF 当作告警索引，再结合代码仓库源码或 CodeQL 数据库中的源码归档进行补充，这样最终报告就能说明问题从哪里开始、流向哪里，以及应当如何修复。

## When To Use|适用场景

- The raw SARIF tells you a rule fired, but it does not explain the vulnerable path clearly enough. 原始 SARIF 只告诉你某条规则被触发了，但没有足够清晰地解释漏洞路径。
- You need source, sink, call-flow, code snippets, and remediation guidance in one report. 你需要在同一份报告里看到 source、sink、调用流、代码片段和修复建议。
- You have one SARIF file, many SARIF files, or a CodeQL output directory and want a triage-ready report. 你手上有一个 SARIF 文件、多个 SARIF 文件，或者一个 CodeQL 输出目录，并希望生成可直接用于分诊的报告。
- You have a source checkout or CodeQL database and want line-level evidence in the output. 你有源码 checkout 或 CodeQL 数据库，并希望输出中包含行级证据。

Do not use this skill when the user only wants the raw SARIF preserved or only wants a mechanical file conversion with no source-aware analysis.
如果用户只想保留原始 SARIF，或者只想做机械式文件转换而不需要结合源码分析，就不要使用这个技能。

## Inputs|输入

Accept either 接受以下任一输入：

- One SARIF file
- One directory containing SARIF files

Optional enrichment inputs 可选的增强输入：

- `--source-root`: repository checkout used to load source snippets. 用于加载源码片段的仓库 checkout
- `--codeql-db`: CodeQL database directory used for metadata and `src.zip` fallback. CodeQL 数据库目录，用于读取元数据，并在需要时回退到 `src.zip`

Prefer explicit metadata such as repository path, commit or tag, scan time, and language when available.如果能拿到明确的元数据，优先提供仓库路径、commit 或 tag、扫描时间和语言信息。

## Output Contract|输出约定

Always generate 始终生成：

- `normalized.json`

- `summary.json`

- `report.md`

- `llm_analysis.md`

- `fix_plan.md`

  

## Workflow|工作流程

1. Validate the SARIF payload before any transformation.在进行任何转换前，先校验 SARIF 载荷。
   Require at least `runs[0]` and fail fast on malformed input.至少要求存在 `runs[0]`，如果输入格式错误就尽快失败。
2. Normalize each finding into a stable schema.把每条告警规范化为稳定的统一结构。
3. Extract rule id, rule name, message, severity, security severity, primary location, tags, taxonomies, related locations, and SARIF code-flow steps.提取 rule id、rule name、message、severity、security severity、primary location、tags、taxonomies、related locations，以及 SARIF 中的 code-flow steps。
4. Deduplicate deterministically.以确定性方式去重。
5. Use `(rule_id, file, line, compact_message)` as the fingerprint basis.使用 `(rule_id, file, line, compact_message)` 作为指纹基础。
6. Enrich with source evidence.用源码证据补充告警信息。
7. Prefer `--source-root` for snippets and fall back to `codeql-db/src.zip` when the checkout is missing or incomplete.优先通过 `--source-root` 加载代码片段；如果 checkout 缺失或不完整，则回退到 `codeql-db/src.zip`。
8. Summarize the source-to-sink path.汇总从 source 到 sink 的路径。
9. For every finding, derive source location, sink location, step count, and touched files.对每条告警提取 source 位置、sink 位置、步骤数以及涉及的文件。
10. Render a detailed security report.生成详细的安全报告。
11. The report must answer where tainted data enters, where it reaches the dangerous sink, what evidence exists, which code lines matter, and what remediation pattern fits the issue.报告必须回答污点数据从哪里进入、在哪里到达危险 sink、有哪些证据、哪些代码行最关键，以及适合该问题的修复模式是什么。
12. Generate the extended analysis artifacts as Markdown.以 Markdown 形式生成扩展分析产物。
13. `llm_analysis.md` should summarize the overall assessment, rule clusters, notable findings, and confidence notes in a readable format.`llm_analysis.md` 应以可读格式总结总体评估、规则聚类、重点告警和置信度说明。
14. `fix_plan.md` should focus on remediation order, target files, verification goals, and rollout priorities.`fix_plan.md` 应重点说明修复顺序、目标文件、验证目标以及落地优先级。
15. Be explicit about limits.明确说明能力边界和限制。
16. If source snippets are unavailable, say the report is SARIF-only.如果拿不到源码片段，要明确说明报告是基于 SARIF-only 的分析。
17. If a CodeQL database is present but the local `codeql` CLI is unavailable, do not claim database query expansion happened.如果存在 CodeQL 数据库但本地没有可用的 `codeql` CLI，就不要声称执行过数据库查询扩展。

## Scripts|脚本

Use bundled scripts before writing ad-hoc code 在编写临时代码之前，先使用随附脚本：

- `scripts/normalize_sarif.py`
- `scripts/render_report.py`

Patch these scripts first when required functionality is missing. 如果缺少所需功能，应优先修改这些脚本，而不是另写一套临时代码。

## Commands|命令

Single SARIF plus source checkout  单个 SARIF 加源码 checkout：

```bash
python scripts/normalize_sarif.py \
  --input path/to/result.sarif \
  --out out/normalized.json \
  --source-root /path/to/repo

python scripts/render_report.py \
  --input out/normalized.json \
  --out-dir out
```

Directory of SARIF files with CodeQL DB fallback  包含多个 SARIF 文件的目录，并以 CodeQL DB 作为回退来源：

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

## Quality Gates|质量门禁

- Raw count, normalized count, and duplicates removed must reconcile. 原始数量、规范化后的数量以及去重移除的数量必须能相互对上。
- Every finding must contain `rule_id` plus a primary location or explicit `unknown`. 每条告警都必须包含 `rule_id`，以及一个 primary location，或者显式标记为 `unknown`。
- `summary.json` risk bucket totals must equal the total finding count. `summary.json` 中各风险分桶的总数必须等于告警总数。
- `report.md` must include primary location, source and sink, call flow, vulnerability mechanism, and remediation guidance. `report.md` 必须包含 primary location、source 和 sink、调用流、漏洞机理以及修复建议。
- If source context is unavailable, the report must say so instead of implying that line-level review happened. 如果拿不到源码上下文，报告必须明确写出来，不能暗示已经做过行级审查。
- `llm_analysis.md` and `fix_plan.md` must stay readable and audience-facing. Do not dump raw JSON structures into those Markdown files. `llm_analysis.md` 和 `fix_plan.md` 必须保持可读、面向读者；不要把原始 JSON 结构直接倾倒进这些 Markdown 文件里。

## Safety Boundaries|安全边界

- Do not execute code from SARIF snippets. 不要执行来自 SARIF 片段中的代码。
- Do not claim exploitability certainty without direct evidence. 在没有直接证据的情况下，不要声称漏洞一定可利用。
- Do not claim CodeQL DB query expansion unless you actually queried it. 如果你实际上没有查询 CodeQL DB，就不要声称做过数据库查询扩展。
- Keep raw SARIF separate from derived artifacts. 保持原始 SARIF 与派生产物分离。
