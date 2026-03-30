#!/usr/bin/env python3
import argparse
import json
import os
from collections import Counter


RISK_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, help="normalized.json path")
    parser.add_argument("--out-dir", required=True, help="output directory")
    parser.add_argument("--top", type=int, default=10, help="number of findings to render in detail")
    return parser.parse_args()


def load_json(path):
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def rule_category(finding):
    rule_id = (finding.get("rule_id") or "").lower()
    cwe = {item.upper() for item in finding.get("taxonomies", {}).get("cwe", [])}
    tags = {str(tag).lower() for tag in finding.get("tags", [])}

    if "command-line-injection" in rule_id or "CWE-78" in cwe:
        return "command-injection"
    if "sql" in rule_id or "CWE-89" in cwe:
        return "sql-injection"
    if "path" in rule_id or "CWE-22" in cwe:
        return "path-traversal"
    if "xss" in rule_id or "cross-site-scripting" in rule_id or "CWE-79" in cwe:
        return "xss"
    if "security" in tags:
        return "generic-security"
    return "generic"


def describe_mechanism(finding):
    flow = finding.get("flow_summary", {})
    source = flow.get("source", {})
    sink = flow.get("sink", {})
    category = rule_category(finding)
    source_desc = f"{source.get('file', 'unknown')}:{source.get('line', 0)}"
    sink_desc = f"{sink.get('file', 'unknown')}:{sink.get('line', 0)}"

    if category == "command-injection":
        return (
            f"Untrusted data enters at {source_desc} and reaches a shell-command construction sink at {sink_desc}. "
            "The vulnerable pattern is string-based command assembly, which allows shell metacharacters or attacker-controlled arguments "
            "to change the command that ultimately executes."
        )
    if category == "sql-injection":
        return (
            f"Input introduced at {source_desc} propagates into a database execution path at {sink_desc} without reliable parameter binding. "
            "That makes query structure attacker-influenced instead of data-only."
        )
    if category == "path-traversal":
        return (
            f"Input introduced at {source_desc} influences file-system access at {sink_desc}. "
            "Without canonicalization and allowlisting, attacker-controlled path components can escape the intended directory boundary."
        )
    if category == "xss":
        return (
            f"Data originating at {source_desc} reaches an HTML or script rendering sink at {sink_desc} without confirmed output encoding. "
            "That creates a path for attacker-supplied script content to execute in a browser context."
        )
    return (
        f"Data enters at {source_desc} and reaches a sensitive operation at {sink_desc}. "
        "The SARIF evidence shows a source-to-sink path, but the code does not demonstrate a sufficient validation or neutralization boundary on that path."
    )


def remediation_guidance(finding):
    category = rule_category(finding)
    if category == "command-injection":
        return [
            "Replace shell string concatenation with an argument-vector process API so user-controlled data is never interpreted by a shell.",
            "If a shell cannot be avoided, constrain the input with a strict allowlist and reject characters that alter shell syntax or command boundaries.",
            "Separate trusted executable selection from untrusted runtime parameters, and keep environment-variable values out of command templates.",
            "Add regression coverage that proves dangerous payloads remain data and do not change the executed command.",
        ]
    if category == "sql-injection":
        return [
            "Use parameterized queries or prepared statements for every untrusted value.",
            "Keep query shape constant and move user input into bind variables instead of string concatenation.",
            "Add regression tests for quotes, comments, and boolean-toggling payloads.",
        ]
    if category == "path-traversal":
        return [
            "Canonicalize the path before use and enforce that the resolved path stays under an allowed base directory.",
            "Allowlist expected filenames or extensions instead of accepting arbitrary path fragments.",
            "Add regression tests for `..`, absolute-path, and encoded traversal payloads.",
        ]
    if category == "xss":
        return [
            "Apply context-appropriate output encoding at the final rendering sink.",
            "Prefer safe templating APIs that escape by default and avoid raw HTML insertion.",
            "Add regression tests for script-tag, event-handler, and attribute-breaking payloads.",
        ]
    return [
        "Define the trust boundary on the data-flow path and enforce validation or neutralization before the sink.",
        "Prefer APIs that preserve structure and treat untrusted input as data instead of executable syntax.",
        "Add a regression test that exercises the exact source-to-sink path described in the SARIF evidence.",
    ]


def format_location(location):
    return f"{location.get('file', 'unknown')}:{location.get('line', 0)}"


def render_snippet(snippet):
    if not snippet or not snippet.get("available"):
        return ["Source snippet unavailable."]
    rendered = ["```text"]
    focus_line = snippet.get("focus_line", 0)
    for line in snippet.get("lines", []):
        marker = ">" if line.get("line") == focus_line else " "
        rendered.append(f"{marker} {line.get('line'):>4} | {line.get('text', '')}")
    rendered.append("```")
    return rendered


def render_call_flow(finding):
    steps = finding.get("thread_flow_steps") or []
    if not steps:
        steps = finding.get("related_locations") or []
    if not steps:
        return ["No explicit call-flow steps were recorded in the SARIF payload."]

    lines = []
    for index, step in enumerate(steps, start=1):
        message = step.get("message") or "flow step"
        lines.append(f"{index}. `{format_location(step)}` - {message}")
    return lines


def top_findings(findings, limit):
    return sorted(findings, key=lambda item: (RISK_ORDER.get(item.get("risk", "info"), 99), item.get("rule_id", "")))[:limit]


def build_summary(data):
    findings = data.get("findings", [])
    risk_counter = Counter(finding.get("risk", "info") for finding in findings)
    rule_counter = Counter(finding.get("rule_id", "unknown") for finding in findings)
    file_counter = Counter(finding.get("file", "unknown") for finding in findings)

    summary = {
        "total": len(findings),
        "risk_counts": dict(risk_counter),
        "top_rules": rule_counter.most_common(10),
        "top_files": file_counter.most_common(10),
        "findings_with_code_flow": sum(1 for finding in findings if finding.get("thread_flow_steps")),
        "findings_with_source_context": sum(
            1 for finding in findings if finding.get("source_context", {}).get("primary", {}).get("available")
        ),
        "enrichment": {
            "source_root": data.get("meta", {}).get("source_root"),
            "source_enrichment": bool(data.get("meta", {}).get("source_enrichment")),
            "codeql_db": data.get("meta", {}).get("codeql_db", {}),
        },
    }
    return summary, risk_counter, rule_counter, file_counter


def main():
    args = parse_args()
    data = load_json(args.input)
    findings = data.get("findings", [])
    summary, risk_counter, rule_counter, file_counter = build_summary(data)

    os.makedirs(args.out_dir, exist_ok=True)
    summary_path = os.path.join(args.out_dir, "summary.json")
    report_path = os.path.join(args.out_dir, "report.md")

    with open(summary_path, "w", encoding="utf-8") as handle:
        json.dump(summary, handle, ensure_ascii=False, indent=2)

    lines = []
    lines.append("# Detailed SARIF Security Report")
    lines.append("")
    lines.append("## Executive Summary")
    lines.append(f"- Total findings: {len(findings)}")
    for risk in ["critical", "high", "medium", "low", "info"]:
        lines.append(f"- {risk}: {risk_counter.get(risk, 0)}")
    lines.append(f"- Findings with explicit call flow: {summary['findings_with_code_flow']}")
    lines.append(f"- Findings with source snippets: {summary['findings_with_source_context']}")
    lines.append("")
    lines.append("## Analysis Inputs")
    lines.append(f"- Normalized input: `{args.input}`")
    lines.append(f"- Source root: `{data.get('meta', {}).get('source_root') or 'not provided'}`")
    codeql_db = data.get("meta", {}).get("codeql_db", {})
    if codeql_db.get("path"):
        db_status = "available" if codeql_db.get("available") else "missing"
        cli_status = "available" if codeql_db.get("cli_available") else "not detected"
        lines.append(f"- CodeQL DB: `{codeql_db.get('path')}` ({db_status}, CLI {cli_status})")
    else:
        lines.append("- CodeQL DB: not provided")
    lines.append("")
    lines.append("## Hotspots")
    for file_name, count in file_counter.most_common(10):
        lines.append(f"- `{file_name}`: {count} finding(s)")
    lines.append("")
    lines.append("## Top Rules")
    for rule_id, count in rule_counter.most_common(10):
        lines.append(f"- `{rule_id}`: {count}")
    lines.append("")
    lines.append("## Detailed Findings")

    for finding in top_findings(findings, args.top):
        lines.append("")
        lines.append(f"### {finding.get('id')} - {finding.get('rule_id')} ({finding.get('risk')})")
        lines.append(f"- Primary Location: `{finding.get('file')}:{finding.get('start_line')}`")
        lines.append(f"- Rule Name: {finding.get('rule_name') or finding.get('rule_id')}")
        lines.append(f"- Severity: `{finding.get('severity')}`")
        if finding.get("security_severity"):
            lines.append(f"- Security Severity: `{finding.get('security_severity')}`")
        if finding.get("taxonomies", {}).get("cwe"):
            lines.append(f"- CWE: {', '.join(finding['taxonomies']['cwe'])}")
        if finding.get("taxonomies", {}).get("owasp"):
            lines.append(f"- OWASP: {', '.join(finding['taxonomies']['owasp'])}")
        lines.append(f"- Message: {finding.get('message')}")

        lines.append("")
        lines.append("#### Trigger and Sink")
        flow = finding.get("flow_summary", {})
        lines.append(f"- Source: `{format_location(flow.get('source', {}))}`")
        lines.append(f"- Sink: `{format_location(flow.get('sink', {}))}`")
        lines.append(f"- Observed flow steps: {flow.get('step_count', 0)}")

        lines.append("")
        lines.append("#### Call Flow")
        lines.extend(render_call_flow(finding))

        lines.append("")
        lines.append("#### Vulnerability Mechanism")
        lines.append(describe_mechanism(finding))

        lines.append("")
        lines.append("#### Source Evidence")
        lines.extend(render_snippet(finding.get("source_context", {}).get("primary")))

        related_snippets = finding.get("source_context", {}).get("related", [])
        if related_snippets:
            lines.append("")
            lines.append("#### Supporting Evidence")
            for snippet in related_snippets[:3]:
                label = snippet.get("label") or "related evidence"
                lines.append(f"- {label}")
                lines.extend(render_snippet(snippet))

        lines.append("")
        lines.append("#### Remediation Guidance")
        for item in remediation_guidance(finding):
            lines.append(f"- {item}")

        lines.append("")
        lines.append("#### Confidence Notes")
        notes = []
        if finding.get("thread_flow_steps"):
            notes.append("The call flow is backed by SARIF code-flow steps.")
        else:
            notes.append("The report falls back to related locations because no explicit SARIF code-flow steps were present.")
        if finding.get("source_context", {}).get("primary", {}).get("available"):
            notes.append("Primary source context was loaded from the checkout for line-level explanation.")
        else:
            notes.append("Primary source context was unavailable, so the explanation is based only on SARIF metadata.")
        if codeql_db.get("path") and not codeql_db.get("cli_available"):
            notes.append("A CodeQL database path was supplied, but the local `codeql` CLI was not detected, so no DB query expansion was performed.")
        for note in notes:
            lines.append(f"- {note}")

    with open(report_path, "w", encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
