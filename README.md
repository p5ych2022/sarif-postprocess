# sarif-postprocess|sarif-postprocess

`sarif-postprocess` is a source-aware SARIF analysis skill. `sarif-postprocess` 是一个结合源码上下文的 SARIF 分析技能。

It turns raw SARIF into a report that explains where a finding starts, where it ends, what the observed path looks like, and how the issue should be fixed. 它会把原始 SARIF 转换成一份报告，说明告警从哪里开始、到哪里结束、观察到的路径是什么样，以及这个问题应该如何修复。

## What The Skill Produces|这个技能会产出什么

It always generates  它始终会生成：

- `normalized.json`
- `summary.json`
- `report.md`
- `llm_analysis.md`
- `fix_plan.md`

## Inputs|输入

The required input is either one SARIF file or one directory containing SARIF files. 必需输入可以是单个 SARIF 文件，也可以是包含多个 SARIF 文件的目录。

Optional inputs  可选输入包括：

- `--source-root`: repository checkout used to load source snippets  用于加载源码片段的仓库 checkout
- `--codeql-db`: CodeQL database directory  CodeQL 数据库目录

If `src.zip` exists in the database, the scripts can load source snippets from that archive even when a checkout is unavailable. 如果数据库中存在 `src.zip`，那么即使本地没有 checkout，脚本也能从该源码归档中加载代码片段。

## Bundled Scripts|随附脚本

The skill ships with  这个技能自带以下脚本：

- `scripts/normalize_sarif.py`
- `scripts/render_report.py`

`normalize_sarif.py` validates SARIF, normalizes findings, extracts taxonomies, deduplicates records, and loads source context. `normalize_sarif.py` 会校验 SARIF、规范化告警、提取分类信息、对记录去重，并加载源码上下文。

`render_report.py` builds `summary.json` and renders a detailed `report.md`.  `render_report.py` 会生成 `summary.json`，并渲染详细的 `report.md`。

## Report Structure|报告结构

The generated report is meant to answer triage questions quickly. 生成的报告旨在快速回答分诊阶段最关心的问题。

Typical sections include  典型章节包括：

- Executive Summary
- Analysis Inputs
- Hotspots
- Top Rules
- Detailed Findings

Each finding section should include the primary location, source and sink, call flow, vulnerability mechanism, source evidence, remediation guidance, and confidence notes when available. 每个告警章节都应包含 primary location、source 和 sink、调用流、漏洞机理、源码证据、修复建议，以及在可用时附带置信度说明。

## Extra Markdown Artifacts|额外的 Markdown 产物

The extended analysis artifacts should be readable Markdown  扩展分析产物应当是可读的 Markdown：

- `llm_analysis.md`: overall assessment, rule clusters, notable findings, confidence notes.  总体评估、规则聚类、重点告警、置信度说明
- `fix_plan.md`: remediation order, target files, verification strategy, rollout priorities.  修复顺序、目标文件、验证策略、落地优先级

## Typical Usage|典型用法

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

Multiple SARIF files plus CodeQL database  多个 SARIF 文件加 CodeQL 数据库：

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

## Fallback Behavior|回退行为

This skill should be explicit about what evidence was used.  这个技能应当明确说明实际使用了哪些证据来源。

- If `--source-root` is provided and the files exist, the report should include line-level snippets from the checkout.  如果提供了 `--source-root` 且文件存在，报告应包含来自 checkout 的行级代码片段。
- If the checkout is missing but `--codeql-db` contains `src.zip`, the scripts should use that source archive instead.  如果 checkout 不存在但 `--codeql-db` 中包含 `src.zip`，脚本应改用该源码归档。
- If neither source path works, the report should fall back to SARIF-only analysis and say so clearly.  如果两种源码路径都不可用，报告应回退为仅基于 SARIF 的分析，并明确说明这一点。
- If a CodeQL database path is provided but the local `codeql` CLI is unavailable, the report must not imply that live database queries were executed.  如果提供了 CodeQL 数据库路径，但本地 `codeql` CLI 不可用，报告绝不能暗示执行过实时数据库查询。

## Quality Gates|质量门禁

- Counts across raw SARIF, normalized findings, and duplicates removed must reconcile.  原始 SARIF、规范化结果和去重移除数量之间的计数必须一致。
- Every finding must have a rule id and a location, or an explicit `unknown` marker.  每条告警都必须有 rule id 和位置信息，否则就必须带显式的 `unknown` 标记。
- Risk bucket totals in `summary.json` must equal the total finding count.  `summary.json` 中各风险分桶的总数必须等于告警总数。
- `report.md` must include source and sink, call flow, vulnerability mechanism, and remediation guidance.  `report.md` 必须包含 source 和 sink、调用流、漏洞机理以及修复建议。
- `llm_analysis.md` must read like a report for humans, not a serialized data dump.  `llm_analysis.md` 必须读起来像给人看的报告，而不是序列化后的数据转储。
