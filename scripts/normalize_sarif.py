#!/usr/bin/env python3
import argparse
import hashlib
import json
import os
import shutil
from datetime import datetime, timezone
from pathlib import Path
from zipfile import ZipFile


def compact_text(value):
    return " ".join((value or "").split())


def safe_int(value, default=0):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, help="SARIF file or directory path")
    parser.add_argument("--out", required=True, help="normalized JSON output path")
    parser.add_argument("--source-root", help="source checkout root used to load code snippets")
    parser.add_argument("--codeql-db", help="optional CodeQL database path for metadata and downstream analysis")
    parser.add_argument("--snippet-radius", type=int, default=3, help="lines of source context before and after focus line")
    return parser.parse_args()


def iter_sarif_inputs(input_path):
    path = Path(input_path)
    if path.is_file():
        return [path]
    if not path.is_dir():
        raise SystemExit(f"Input path does not exist: {input_path}")

    files = sorted(
        [
            item
            for item in path.rglob("*")
            if item.is_file() and (item.name.endswith(".sarif") or item.name.endswith(".sarif.json"))
        ]
    )
    if not files:
        raise SystemExit(f"No SARIF files found under: {input_path}")
    return files


def load_json(path):
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def to_risk(result, rule, has_code_flow):
    props = rule.get("properties", {}) if isinstance(rule, dict) else {}
    sec = props.get("security-severity") or rule.get("security-severity") if isinstance(rule, dict) else None
    if sec is not None:
        try:
            score = float(str(sec))
            if score >= 9.0:
                risk = "critical"
            elif score >= 7.0:
                risk = "high"
            elif score >= 4.0:
                risk = "medium"
            elif score > 0:
                risk = "low"
            else:
                risk = "info"
        except Exception:
            risk = "info"
    else:
        severity = (result.get("level") or "").lower()
        risk = {
            "error": "high",
            "warning": "medium",
            "note": "info",
            "recommendation": "low",
        }.get(severity, "info")

    tags = [str(tag).lower() for tag in (props.get("tags") or [])]
    if risk == "info" and any("security" in tag for tag in tags):
        risk = "medium"
    if has_code_flow and risk == "medium":
        risk = "high"
    return risk


def parse_physical_location(physical_location):
    location = physical_location or {}
    artifact = location.get("artifactLocation", {}) or {}
    region = location.get("region", {}) or {}
    return {
        "file": artifact.get("uri") or "unknown",
        "line": safe_int(region.get("startLine"), 0),
        "column": safe_int(region.get("startColumn"), 0),
        "end_line": safe_int(region.get("endLine"), safe_int(region.get("startLine"), 0)),
        "end_column": safe_int(region.get("endColumn"), safe_int(region.get("startColumn"), 0)),
    }


def parse_related_locations(result):
    related = []
    for item in result.get("relatedLocations") or []:
        location = parse_physical_location(item.get("physicalLocation"))
        location["message"] = compact_text((item.get("message") or {}).get("text") or "")
        location["id"] = item.get("id")
        related.append(location)
    return related


def parse_thread_flow_steps(result):
    steps = []
    code_flows = result.get("codeFlows") or []
    for flow_index, code_flow in enumerate(code_flows, start=1):
        for thread_index, thread_flow in enumerate(code_flow.get("threadFlows") or [], start=1):
            for step_index, item in enumerate(thread_flow.get("locations") or [], start=1):
                location = item.get("location") or {}
                parsed = parse_physical_location(location.get("physicalLocation"))
                parsed["message"] = compact_text((location.get("message") or {}).get("text") or "")
                parsed["nesting_level"] = safe_int(item.get("nestingLevel"), 0)
                parsed["execution_order"] = {
                    "flow": flow_index,
                    "thread": thread_index,
                    "step": step_index,
                }
                steps.append(parsed)
    return steps


def dedupe_locations(locations):
    seen = set()
    deduped = []
    for item in locations:
        key = (
            item.get("file"),
            item.get("line"),
            item.get("column"),
            item.get("message"),
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)
    return deduped


def extract_taxonomies(rule):
    tags = [str(tag) for tag in (rule.get("properties", {}).get("tags") or [])]
    cwe = []
    owasp = []
    for tag in tags:
        lowered = tag.lower()
        if "cwe-" in lowered:
            cwe.append(lowered.split("cwe-")[-1].split("/")[0])
        if "owasp/" in lowered:
            owasp.append(tag.split("/")[-1].upper())
    return {
        "cwe": [f"CWE-{item.upper()}" for item in sorted(set(cwe))],
        "owasp": sorted(set(owasp)),
    }


def resolve_source_path(source_root, file_path):
    if not source_root or not file_path or file_path == "unknown":
        return None
    candidate = Path(file_path)
    if candidate.is_absolute() and candidate.exists():
        return candidate
    joined = Path(source_root) / candidate
    if joined.exists():
        return joined
    return None


def parse_simple_yaml(path):
    data = {}
    if not path or not Path(path).exists():
        return data
    for raw_line in Path(path).read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or ":" not in line:
            continue
        key, value = line.split(":", 1)
        data[key.strip()] = value.strip().strip("'\"")
    return data


def load_codeql_db_metadata(codeql_db):
    if not codeql_db:
        return {
            "path": None,
            "available": False,
            "cli_available": shutil.which("codeql") is not None,
            "has_source_archive": False,
        }

    db_path = Path(codeql_db)
    baseline_path = db_path / "baseline-info.json"
    yml_path = db_path / "codeql-database.yml"
    baseline = load_json(baseline_path) if baseline_path.exists() else {}
    database = parse_simple_yaml(yml_path)
    language_summary = []
    for entry in (baseline.get("languages") or {}).values():
        language_summary.append(
            {
                "name": entry.get("name"),
                "display_name": entry.get("displayName"),
                "lines_of_code": entry.get("linesOfCode"),
                "file_count": len(entry.get("files") or []),
            }
        )

    metadata = {
        "path": str(db_path.resolve()),
        "available": db_path.exists(),
        "cli_available": shutil.which("codeql") is not None,
        "has_source_archive": (db_path / "src.zip").exists(),
        "languages": language_summary,
        "primary_language": database.get("primaryLanguage"),
        "baseline_lines_of_code": database.get("baselineLinesOfCode"),
        "sha": database.get("sha"),
        "creation_time": database.get("creationTime"),
        "cli_version": database.get("cliVersion"),
    }
    return metadata


def load_snippet_from_codeql_db(codeql_db, file_path, focus_line, radius):
    if not codeql_db or focus_line <= 0:
        return None

    src_zip = Path(codeql_db) / "src.zip"
    if not src_zip.exists():
        return None

    normalized = str(Path(file_path)).replace("\\", "/").lstrip("/")
    candidates = [normalized, f"src/{normalized}"]

    with ZipFile(src_zip) as archive:
        members = {name.lstrip("/"): name for name in archive.namelist()}
        match = None
        for candidate in candidates:
            if candidate in members:
                match = members[candidate]
                break
        if match is None:
            for name in members:
                if name.endswith(normalized):
                    match = members[name]
                    break
        if match is None:
            return None

        with archive.open(match) as handle:
            text = handle.read().decode("utf-8", errors="replace")

    contents = text.splitlines()
    start_line = max(1, focus_line - radius)
    end_line = min(len(contents), focus_line + radius)
    lines = [{"line": line_no, "text": contents[line_no - 1]} for line_no in range(start_line, end_line + 1)]
    return {
        "available": True,
        "path": f"{src_zip}!/{match}",
        "focus_line": focus_line,
        "start_line": start_line,
        "end_line": end_line,
        "lines": lines,
    }


def load_snippet(source_root, codeql_db, file_path, focus_line, radius):
    resolved = resolve_source_path(source_root, file_path)
    if resolved is None or focus_line <= 0:
        fallback = load_snippet_from_codeql_db(codeql_db, file_path, focus_line, radius)
        if fallback is not None:
            fallback["origin"] = "codeql-db"
            return fallback
        return {
            "available": False,
            "path": str((Path(source_root) / file_path) if source_root and file_path else file_path or "unknown"),
            "focus_line": focus_line,
            "start_line": 0,
            "end_line": 0,
            "lines": [],
            "origin": "missing",
        }

    try:
        contents = resolved.read_text(encoding="utf-8").splitlines()
    except UnicodeDecodeError:
        contents = resolved.read_text(encoding="latin-1").splitlines()

    start_line = max(1, focus_line - radius)
    end_line = min(len(contents), focus_line + radius)
    lines = [{"line": line_no, "text": contents[line_no - 1]} for line_no in range(start_line, end_line + 1)]
    return {
        "available": True,
        "path": str(resolved),
        "focus_line": focus_line,
        "start_line": start_line,
        "end_line": end_line,
        "lines": lines,
        "origin": "source-root",
    }


def build_source_context(source_root, codeql_db, primary_location, related_locations, flow_steps, radius):
    primary = load_snippet(source_root, codeql_db, primary_location.get("file"), primary_location.get("line"), radius)

    related = []
    seen = set()
    candidates = related_locations + flow_steps
    for item in candidates:
        key = (item.get("file"), item.get("line"))
        if item.get("file") == primary_location.get("file") and item.get("line") == primary_location.get("line"):
            continue
        if item.get("line", 0) <= 0 or key in seen:
            continue
        seen.add(key)
        snippet = load_snippet(source_root, codeql_db, item.get("file"), item.get("line"), radius)
        snippet["label"] = item.get("message") or "related evidence"
        related.append(snippet)
        if len(related) >= 4:
            break

    return {
        "primary": primary,
        "related": related,
    }


def summarize_flow(primary_location, related_locations, flow_steps):
    ordered_steps = flow_steps or related_locations or [primary_location]
    ordered_steps = [item for item in ordered_steps if item.get("file") or item.get("line")]
    source = ordered_steps[0] if ordered_steps else primary_location
    sink = primary_location if primary_location.get("file") != "unknown" else (ordered_steps[-1] if ordered_steps else primary_location)

    for item in ordered_steps:
        file_name = item.get("file") or ""
        if not file_name.startswith("file:///usr/include"):
            source = item
            break

    for item in reversed(ordered_steps):
        file_name = item.get("file") or ""
        if file_name and not file_name.startswith("file:///usr/include"):
            sink = item
            break

    files = []
    seen = set()
    for item in ordered_steps:
        current = item.get("file") or "unknown"
        if current not in seen:
            seen.add(current)
            files.append(current)
    return {
        "source": source,
        "sink": sink,
        "step_count": len(ordered_steps),
        "files": files,
    }


def normalize_result(result, rule, idx, sarif_file, source_root, codeql_db, snippet_radius):
    message = compact_text(((result.get("message") or {}).get("text")) or "")
    primary_location = parse_physical_location(
        ((result.get("locations") or [{}])[0] or {}).get("physicalLocation")
    )
    primary_location["message"] = message

    related_locations = dedupe_locations(parse_related_locations(result))
    thread_flow_steps = dedupe_locations(parse_thread_flow_steps(result))
    flow_summary = summarize_flow(primary_location, related_locations, thread_flow_steps)
    source_context = build_source_context(
        source_root,
        codeql_db,
        primary_location,
        related_locations,
        thread_flow_steps,
        snippet_radius,
    )
    fingerprint_source = "|".join(
        [
            result.get("ruleId", "unknown"),
            primary_location.get("file", "unknown"),
            str(primary_location.get("line", 0)),
            compact_text(message),
        ]
    )

    return {
        "id": f"F-{idx:06d}",
        "fingerprint": hashlib.sha1(fingerprint_source.encode("utf-8")).hexdigest(),
        "rule_id": result.get("ruleId", "unknown"),
        "rule_name": rule.get("name")
        or (rule.get("shortDescription") or {}).get("text")
        or result.get("ruleId", "unknown"),
        "message": message,
        "severity": result.get("level") or "unknown",
        "security_severity": str(rule.get("properties", {}).get("security-severity", "")),
        "risk": to_risk(result, rule, bool(thread_flow_steps)),
        "file": primary_location.get("file", "unknown"),
        "start_line": primary_location.get("line", 0),
        "start_column": primary_location.get("column", 0),
        "end_line": primary_location.get("end_line", primary_location.get("line", 0)),
        "end_column": primary_location.get("end_column", primary_location.get("column", 0)),
        "tags": rule.get("properties", {}).get("tags", []) if isinstance(rule.get("properties", {}).get("tags", []), list) else [],
        "taxonomies": extract_taxonomies(rule),
        "primary_location": primary_location,
        "related_locations": related_locations,
        "thread_flow_steps": thread_flow_steps,
        "flow_summary": flow_summary,
        "source_context": source_context,
        "evidence": {
            "has_code_flow": bool(thread_flow_steps),
            "code_flow_step_count": len(thread_flow_steps),
            "related_location_count": len(related_locations),
            "source_snippet_available": source_context["primary"]["available"],
        },
        "provenance": {
            "sarif_file": str(sarif_file),
        },
        "raw": {
            "result": result,
        },
    }


def main():
    args = parse_args()
    sarif_inputs = iter_sarif_inputs(args.input)
    source_root = str(Path(args.source_root).resolve()) if args.source_root else None
    codeql_db_path = str(Path(args.codeql_db).resolve()) if args.codeql_db else None

    findings = []
    seen = set()
    total_raw = 0

    for sarif_file in sarif_inputs:
        sarif = load_json(sarif_file)
        runs = sarif.get("runs", [])
        if not runs:
            raise SystemExit(f"Invalid SARIF: missing runs in {sarif_file}")

        run = runs[0]
        rule_map = {}
        driver_rules = run.get("tool", {}).get("driver", {}).get("rules", []) or []
        for rule in driver_rules:
            rule_map[rule.get("id", "unknown")] = rule

        raw_results = run.get("results", []) or []
        total_raw += len(raw_results)

        for result in raw_results:
            rule = rule_map.get(result.get("ruleId", "unknown"), {})
            finding = normalize_result(
                result,
                rule,
                len(findings) + 1,
                sarif_file,
                source_root,
                codeql_db_path,
                args.snippet_radius,
            )
            if finding["fingerprint"] in seen:
                continue
            seen.add(finding["fingerprint"])
            findings.append(finding)

    codeql_db_meta = load_codeql_db_metadata(codeql_db_path)
    output = {
        "meta": {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "input_path": str(Path(args.input).resolve()),
            "sarif_files": [str(item.resolve()) for item in sarif_inputs],
            "source_root": source_root,
            "source_enrichment": bool(source_root or codeql_db_meta.get("has_source_archive")),
            "codeql_db": codeql_db_meta,
        },
        "stats": {
            "total_raw": total_raw,
            "total_normalized": len(findings),
            "duplicates_removed": total_raw - len(findings),
        },
        "findings": findings,
    }

    os.makedirs(Path(args.out).parent or ".", exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as handle:
        json.dump(output, handle, ensure_ascii=False, indent=2)


if __name__ == "__main__":
    main()
