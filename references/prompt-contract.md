# Prompt Contract
# 提示词契约

Use deterministic normalization first and LLM analysis second.
先执行确定性归一化，再执行大模型分析。

Input payload should include normalized finding fields only.
输入载荷应仅包含归一化后的漏洞字段。

```json
{
  "finding": {
    "id": "F-000001",
    "rule_id": "...",
    "risk": "high",
    "message": "...",
    "file": "...",
    "start_line": 0,
    "snippet": "optional",
    "tags": []
  }
}
```

Model must return strict JSON with the required keys.
模型必须返回包含必需键的严格 JSON。

```json
{
  "root_cause": "short explanation",
  "exploitability": "conditions and limits",
  "minimal_fix": "smallest practical patch strategy",
  "safer_refactor": "preferred medium-term change",
  "verification": "how to test the fix",
  "confidence": "low|medium|high",
  "assumptions": ["..."]
}
```

Do not accept markdown wrappers around JSON.
不要接受包裹 JSON 的 markdown 文本。

Require explicit uncertainty in assumptions.
必须在 assumptions 中明确不确定性。
