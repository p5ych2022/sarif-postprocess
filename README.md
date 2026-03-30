# sarif-postprocess
# sarif-postprocess

`sarif-postprocess` is a source-aware SARIF analysis skill.
`sarif-postprocess` 是一个面向源码上下文的 SARIF 分析技能。

It turns raw SARIF into a report that explains where a finding starts, where it ends, what the observed path looks like, and how the issue should be fixed.
它会把原始 SARIF 转换成一份报告，解释漏洞从哪里开始、到哪里结束、观察到的路径是什么，以及问题应该如何修复。



## What The Skill Produces
## 这个技能会产出什么

It always generates `normalized.json`, `summary.json`, and `report.md`.
它始终会生成 `normalized.json`、`summary.json` 和 `report.md`。

It can also generate `llm_analysis.json` and `fix_plan.md` when you explicitly ask for them.
如果你明确要求，它还可以额外生成 `llm_analysis.json` 和 `fix_plan.md`。

## Inputs
## 输入

The required input is either one SARIF file or one directory containing SARIF files.
必需输入可以是单个 SARIF 文件，也可以是包含多个 SARIF 文件的目录。

The optional input `--source-root` points to a repository checkout used to load source snippets.
可选输入 `--source-root` 指向源码仓库 checkout，用于加载代码片段。

The optional input `--codeql-db` points to a CodeQL database directory.
可选输入 `--codeql-db` 指向一个 CodeQL 数据库目录。

If `src.zip` exists in the database, the scripts can load source snippets from that archive even when a checkout is unavailable.
如果数据库中存在 `src.zip`，那么即使本地没有 checkout，脚本也能从该源码归档中提取代码片段。

## Bundled Scripts
## 内置脚本

The skill ships with `scripts/normalize_sarif.py` and `scripts/render_report.py`.
这个技能自带 `scripts/normalize_sarif.py` 和 `scripts/render_report.py`。

`normalize_sarif.py` validates SARIF, normalizes findings, extracts taxonomies, deduplicates records, and loads source context.
`normalize_sarif.py` 负责校验 SARIF、归一化 finding、提取分类信息、执行去重，并加载源码上下文。

`render_report.py` builds `summary.json` and renders a detailed `report.md`.
`render_report.py` 负责生成 `summary.json` 并渲染详细的 `report.md`。

## Report Structure
## 报告结构

The generated report is designed to answer triage questions quickly.
生成出的报告是为了快速回答漏洞分诊问题而设计的。

Typical sections include Executive Summary, Analysis Inputs, Hotspots, Top Rules, and Detailed Findings.
典型章节包括执行摘要、分析输入、热点文件、高频规则和详细漏洞项。

Each finding section includes the primary location, source and sink, call flow, vulnerability mechanism, source evidence, remediation guidance, and confidence notes.
每条 finding 都会包含主位置、source 和 sink、调用链、漏洞机理、源码证据、修复建议和置信说明。

## Typical Usage
## 常见用法

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

Multiple SARIF files plus CodeQL database:
多个 SARIF 文件加上 CodeQL 数据库：

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

## Fallback Behavior
## 回退行为

This skill is intentionally explicit about what evidence was used.
这个技能会明确说明到底使用了哪些证据来源。

If `--source-root` is provided and the files exist, the report includes line-level snippets from the checkout.
如果提供了 `--source-root` 且文件存在，报告会包含来自源码 checkout 的行级代码片段。

If the checkout is missing but `--codeql-db` contains `src.zip`, the scripts use that source archive instead.
如果源码 checkout 缺失，但 `--codeql-db` 中存在 `src.zip`，脚本就会改用数据库里的源码归档。

If neither source path works, the report falls back to SARIF-only analysis and says so in the confidence notes.
如果两种源码路径都不可用，报告会退化为仅基于 SARIF 的分析，并在置信说明中明确写出这一点。

If a CodeQL database path is provided but the local `codeql` CLI is unavailable, the report does not pretend that live database queries were executed.
如果提供了 CodeQL database 路径，但本地没有 `codeql` CLI，报告不会假装已经执行了实时数据库查询。

## Quality Gates
Counts across raw SARIF, normalized findings, and duplicates removed must reconcile.
原始 SARIF、归一化 finding 和去重统计三者的数量必须一致。

Every finding must have a rule id and a location, or an explicit `unknown` marker.
每条 finding 都必须包含规则 ID 和位置，或者显式标记为 `unknown`。

Risk bucket totals in `summary.json` must equal the total finding count.
`summary.json` 中风险分桶总和必须等于 finding 总数。

`report.md` must include source and sink, call flow, vulnerability mechanism, and remediation guidance.
`report.md` 必须包含 source 和 sink、调用链、漏洞机理和修复建议。



## Practical Trigger In Codex
## 在 Codex 中的触发方式

You can trigger it with prompts like “Apply `sarif-postprocess` to this SARIF and generate a detailed report”.
你可以用“请对这个 SARIF 应用 `sarif-postprocess` 并生成详细报告”这样的提示来触发它。

You can also ask for source-aware output directly, such as “show me source, sink, call flow, vulnerability mechanism, and fix guidance”.
你也可以直接要求带源码上下文的输出，例如“请给我 source、sink、调用链、漏洞机理和修复建议”。
