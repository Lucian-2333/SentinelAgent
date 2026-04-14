# tests/__init__.py
"""
tests/ 文件夹 — 单元测试与集成测试
═════════════════════════════════════════════════════════════════════════════

【职责概述】
该目录用于验证 SentinelAgent 的核心契约和回归稳定性。
当前重点是数据模型层面的“强约束”验证。

【测试框架】

工具：pytest（项目已配置 pytest-asyncio，便于后续扩展异步测试）

运行命令：
  pytest tests/ -v              # 详细输出
  pytest tests/test_schemas.py # 仅跑某个文件
  pytest -k "pattern"          # 仅跑名称包含 pattern 的测试

【当前已有测试】

tests/test_schemas.py
  - 覆盖 Packet 不可变、空文本校验、ID 自动生成。
  - 覆盖 AuditResult 的证据约束与置信度边界。
  - 覆盖 ConsensusVerdict 基本结构正确性。

【当前覆盖边界】

- 已覆盖：shared/schemas.py 的核心契约。
- 未覆盖：网关路由、Agent 行为回归、Judge 阈值策略、数据库写入。

【后续建议方向】

1. 网关接口测试
   - /health、/api/v1/intercept、/api/v1/audit 的成功与失败分支。

2. Agent 回归测试
   - PatternAgent 典型规则命中样本。
   - ContextAgent 在 API 异常/解析异常下的降级路径。

3. Judge 聚合测试
   - 不同权重与阈值区间下的 status 断言。
   - dissenting_agents 的识别逻辑。

4. 数据库测试
   - init_db、log_request、get_recent_logs 的最小闭环。

【使用建议】

- 日常开发先跑：pytest tests/test_schemas.py -v
- 提交前建议跑：pytest tests/ -v
"""
