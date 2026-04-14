# shared/__init__.py
"""
shared/ 文件夹 — 共享数据模型与契约层
═════════════════════════════════════════════════════════════════════════════

【职责概述】
Shared 文件夹包含整个 SentinelAgent 系统的"单一真理源"（Single Source of Truth）。
它定义了所有组件之间流动的数据结构和枚举，确保：
  ✓ 语言统一 — 所有人说同一套词汇
  ✓ 类型安全 — 运行时强制验证
  ✓ 协议清晰 — Packet 入、ConsensusVerdict 出
  ✓ 反幻觉约束 — Pydantic 内置的业务规则

简单来说：如果 agents/ 是 N 个智能体的具体实现，
那么 shared/ 就是它们必须遵守的"宪法"。

【文件组成】

shared/__init__.py ← 当前模块说明文件

shared/schemas.py ← 核心文件，包含所有数据定义

【schemas.py 的结构】

1. 枚举定义（Enumerations）
   ────────────────────────

   a) SourceType 枚举 — 流量来源标签
      •  HUMAN_USER — 真人用户输入（Web 界面、CLI）
      •  AGENT_UPSTREAM — 另一个 AI Agent 发来的请求
      •  API_CALL — 直接 API 调用
      •  WEBHOOK — 外部系统的 Webhook 回调
      •  INTERNAL — 系统内部生成（测试、演示、定时任务）
      
      用途：追踪流量来源，便于分析和审计
      例子：{"source": "human_user"} 表示真人输入

   b) ThreatCategory 枚举 — 威胁分类（8 种）
      •  BENIGN — 无威胁（正常请求）
      •  SQL_INJECTION — SQL 注入攻击
      •  XSS — 跨站脚本攻击
      •  PROMPT_INJECTION — 提词注入攻击
      •  JAILBREAK — AI 越狱攻击
      •  DATA_EXFILTRATION — 数据泄露企图
      •  PRIVILEGE_ESCALATION — 权限提升企图
      •  UNKNOWN — 未知威胁（无法分类）
      
      所有 Agent 的判决必须从这 8 个中选一个。
      好处：系统统一，不会有 Agent 返回模糊的 "maybe malicious"。

   c) VerdictStatus 枚举 — 最终执行动作（4 种）
      •  ALLOW — 放行（通过无误）
      •  BLOCK — 硬拦截（直接拒绝）
      •  QUARANTINE — 隔离（待人工审查）
      •  PENDING — 待定（Judge 还没决策）
      
      这是网关最终执行的指令。

2. 数据模型（Data Models）
   ──────────────────────

   数据流向与模型关系图：
   
   客户端 HTTP 请求 → 网关 → Packet
                         ↓
   Judge 调度所有 Agent ← Packet
                         ↓
   PatternAgent.analyse(Packet) → AuditResult
   ContextAgent.analyse(Packet) → AuditResult
                         ↓
   Judge 加权汇总 [AuditResult, AuditResult, ...]
                         ↓
   ConsensusVerdict → JSON 返回给客户端

   a) PacketMetadata 类 — Packet 的元数据包装
      ────────────────
      字段说明：
      • source: SourceType — 来源类型（见上）
      • session_id: str — 会话 ID（用来追踪同一用户的多个请求）
      • timestamp: datetime — 网关接收到的 UTC 时刻
      • ip_address: str | None — 来源 IP（如果可用）
      • user_agent: str | None — HTTP User-Agent 字符串
      • endpoint: str | None — 被访问的 API 路径（如 /login）
      • extra: dict — 扩展字段（为未来功能保留）
      
      设计原则：
        ℹ️  元数据只是"参考信息"，不能替代对 raw_text 的分析
        ℹ️  即使 IP 来自受信列表，raw_text 还是要审计
        ℹ️  这是为了防止"这个 IP 没坏过，随便放"的逻辑漏洞

   b) Packet 类 — 原子级审计单位
      ──────────
      字段说明：
      • packet_id: str — UUID-4 形式的全局唯一 ID
      • raw_text: str — 要审计的原始文本（不能为空或空白）
      • metadata: PacketMetadata — 上下文信息
      
      关键特性：
        ✓ 不可变（frozen=True）— 一旦创建就不能改
        ✓ 所有 Agent 看到同一个 Packet — 保证公平性
        ✓ 是整个管道的"事实锚点"— 所有回答都要靠它
      
      反幻觉设计的例子：
        • raw_text "admin' --" 是事实
        • 任何 Agent 都不能编造出 "admin' @@" 的证据
        • 因为它不在原文里

   c) AuditResult 类 — 单个 Agent 的判决
      ──────────────
      字段说明：
      • agent_id: str — 发出此判决的 Agent（如 "pattern_agent_v1"）
      • packet_id: str — 本次审计的 Packet ID（审计链的指针）
      • threat_category: ThreatCategory — 威胁分类（只能 8 选 1）
      • confidence: float — 置信度 [0.0, 1.0]
      • reasoning: str — 人类可读的解释（最少 10 个字符）
      • evidence: list[str] — 从 raw_text 中复制的证据片段
      • analysed_at: datetime — 分析完成时间
      
      反幻觉约束（Pydantic validator）：
        ✗ 非 BENIGN 威胁必须带 evidence（不能空数组）
        ✗ 所有 evidence 片段必须是 raw_text 的子串
        ✓ 只有 BENIGN 可以没有 evidence
      
      这两个约束是系统的心脏，确保 AI 不乱说话。

   d) ConsensusVerdict 类 — Judge 的最终判决
      ────────────────────
      字段说明：
      • packet_id: str — 本次审计的 Packet
      • status: VerdictStatus — 最终动作（ALLOW/BLOCK/...）
      • dominant_threat: ThreatCategory — 多数 Agent 同意的威胁
      • aggregate_confidence: float — 加权后的聚合置信度
      • contributing_agents: list[str] — 支持这个判决的 Agent ID
      • dissenting_agents: list[str] — 反对的 Agent ID
      • judge_reasoning: str — Judge 解释判决的逻辑
      • decided_at: datetime — 判决时间戳
      • raw_audits: list[AuditResult] — 原始 AuditResult 列表（完全透明）
      
      设计特点：
        ✓ 包含了所有中间投票结果（raw_audits）
        ✓ 前端可以展示"哪些 Agent 赞成，哪些反对"
        ✓ 用户可以看到完整的"思考过程"
        ✓ 便于事后审计和合规性检查

3. 契约执行机制（Contract Enforcement）
   ──────────────────────────────────────

   Pydantic 在字段级别和模型级别执行业务规则：

   a) 字段级 validator
      • raw_text 必须 strip() 后非空
      • confidence 必须在 [0.0, 1.0] 范围内
      • reasoning 最少 10 字符（防止空洞回答）
      • evidence 如果是非 BENIGN 威胁，必须非空

   b) 模型级 validator
      • 跨字段检查：AuditResult.evidence_required_for_threats()
      • 如果 threat_category != BENIGN 且 len(evidence) == 0 → 拒绝
      • 这是反幻觉的第一道防线

   c) BaseAgent 的第二道防线
      • agents/base_agent.py 的 _validate_evidence_anchor()
      • 检查所有 evidence 子串是否真的在 raw_text 里
      • 如果检查失败，自动降 confidence 到 0（信号失效）

   两层防守 = 双保险，不怕万一有漏网。

【为什么设计这么严格？】

AI 系统的通病：
  ✗ LLM 容易编造数据（幻觉hallucination）
  ✗ 系统间协议模糊 → 一个说 "threat"，另一个听成了 "maybe"
  ✗ 没有审计线索 → 出错了无法回溯

本设计的答案：
  ✓ 强制证据溯源 — 不能编故事，要靠事实
  ✓ Pydantic 严格校验 — 类型安全语义完备
  ✓ UUID + 时间戳 + 完整审计记录 — 事后可追溯

这样一个系统才值得放在真实环境中运行。

【扩展性】

如果未来要加新的威胁类型（如 "supply_chain_attack"）：
  1. 改 ThreatCategory 枚举 ← 一处改动
  2. Agent 们会自动知道新类别存在
  3. Judge 汇总逻辑不用改（自适应新类别权重）

如果要加新的源类型（如 "mobile_app"）：
  1. 改 SourceType 枚举 ← 一处改动
  2. 全系统自动支持

这就叫"开闭原则"：对扩展开放，对修改闭合。
"""
