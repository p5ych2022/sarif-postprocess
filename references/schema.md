﻿# Normalized Schema
# 归一化结构

Each finding should follow a stable JSON shape.
每条漏洞结果应遵循稳定的 JSON 结构。

```json
{
  "id": "F-000001",
  "fingerprint": "stable-hash",
  "rule_id": "cpp/path-injection",
  "message": "Untrusted input used in file path",
  "severity": "warning",
  "security_severity": "8.1",
  "risk": "high",
  "file": "src/server.cpp",
  "start_line": 42,
  "start_column": 15,
  "end_line": 42,
  "end_column": 35,
  "tags": ["external/cwe/cwe-22"],
  "code_flow_count": 1,
  "has_code_flow": true,
  "raw": {}
}
```

Use a top-level envelope with meta, stats, and findings.
顶层结构应包含 meta、stats 和 findings。

```json
{
  "meta": {
    "source": "local",
    "generated_at": "ISO-8601"
  },
  "stats": {
    "total_raw": 0,
    "total_normalized": 0,
    "duplicates_removed": 0
  },
  "findings": []
}
```

Preserve minimal raw fragments for traceability.
保留最小必要的原始片段用于可追溯性。

Use `unknown` placeholders for missing fields.
缺失字段请使用 `unknown` 占位。
