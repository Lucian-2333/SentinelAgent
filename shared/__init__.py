# shared/__init__.py
"""
shared/ 文件夹 — 共享契约与公共基础设施
═════════════════════════════════════════════════════════════════════════════

【职责概述】
该目录存放全系统共享的“数据契约”和“基础能力”，确保网关、专家、裁决、
前端在同一语义下协作。

【当前文件组成】

1. schemas.py（核心契约）
   - 定义 SourceType / ThreatCategory / VerdictStatus 三类枚举。
   - 定义 PacketMetadata、Packet、AuditResult、ConsensusVerdict 四个核心模型。
   - 使用 Pydantic 进行边界校验与业务约束。

2. database.py（审计日志存储）
   - 基于 aiosqlite 提供异步持久化能力。
   - 启动时由 init_db() 初始化 audit_logs 表。
   - 通过 log_request() 写入审计记录，get_recent_logs() 查询最近记录。

3. llm_client.py（统一 LLM 访问封装）
   - 提供 deepseek / openai / anthropic / openai_compatible 的统一调用入口。
   - 由环境变量选择 provider 和模型参数。

【关键契约规则】

- Packet.raw_text 不能为空白。
- Packet 为 frozen 模型，创建后不可变。
- AuditResult.confidence 必须在 [0.0, 1.0]。
- 非 BENIGN 的 AuditResult 必须提供 evidence。
- ConsensusVerdict 保留 raw_audits，支持完整追溯。

【这一层的价值】

- 让各层共享统一输入输出格式，减少协议漂移。
- 让审计数据可追踪、可查询、可回放。
- 让外部模型接入方式统一，便于切换供应商。
"""
