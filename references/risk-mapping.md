# Risk Mapping
# 风险映射

Apply mapping in strict priority order.
严格按优先级顺序执行映射。

Priority is: security-severity > problem.severity > tag heuristics > default info.
优先级为：security-severity > problem.severity > 标签启发式 > 默认 info。

Map numeric security-severity as follows.
security-severity 数值映射如下。

- >= 9.0 => critical
- >= 9.0 => critical

- >= 7.0 => high
- >= 7.0 => high

- >= 4.0 => medium
- >= 4.0 => medium

- > 0 => low
- > 0 => low

Map problem.severity as follows.
problem.severity 映射如下。

- error => high
- error => high

- warning => medium
- warning => medium

- recommendation => low
- recommendation => low

- note => info
- note => info

Promote risk when data-flow evidence is strong.
当数据流证据较强时可上调风险等级。

Never downgrade risk based on guesses.
不要基于猜测下调风险等级。
