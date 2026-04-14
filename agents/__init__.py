# agents/__init__.py
"""
agents/ 文件夹 — 专家智能体层（Layer N）
═════════════════════════════════════════════════════════════════════════════

【职责概述】
这个文件夹包含 SentinelAgent 的核心"智能体集群"，它们是 1+N+1 架构中的
N（多个专家）。每个智能体都独立分析同一个 Packet，从不同的角度产生
审计结论(AuditResult)，最后由 Judge 层汇总成最终共识(ConsensusVerdict)。

【具体组成】

1. base_agent.py（抽象基类）
   ──────────────────────────
   - BaseAgent：所有具体智能体的父类
   - 定义通用合约：
     • analyse() — 公共入口，负责日志、计时、证据验证
     • _analyse() — 抽象方法，子类必须实现具体逻辑
   - 核心功能1：日志与监测
     • 记录分析开始/完成时间，便于性能追踪
   - 核心功能2：反幻觉卫士
     • _validate_evidence_anchor() 强制所有非 benign 结论必须有证据
     • 如果智能体编造了不在原文中的证据片段，直接降信度到 0
   - 设计意义：确保所有智能体遵守"有凭有据"的原则，不乱报警

2. pattern_agent/（规则签名专家）
   ──────────────────────────────
   - 职责：通过预编译的正则表达式快速识别已知攻击特征
   - 优势：
     • 零依赖性：不需要 LLM，完全本地运行
     • 高确定性：同一个 Payload 每次结果一致
     • 低延迟：毫秒级别返回结果
     • 高精度：规则都是经过实战验证的
   - 检测类型：
     • SQL Injection（SQLi）：注释绕过、恒真条件、UNION 查询等
     • Cross-Site Scripting（XSS）：<script> 标签、事件处理器、js: URI
     • Prompt Injection：忽略前文、替换指令等
   - 工作流程：对输入文本逐一匹配规则，返回匹配到的最高置信度威胁

3. context_agent/（语义意图专家）
   ──────────────────────────────
   - 职责：通过大语言模型理解文本的"真实意图"，检测规则无法覆盖的攻击
   - 优势：
     • 高泛化性：能应对未知或变形攻击
     • 深度推理：能理解"越狱""人格覆盖"等高层攻击
   - 检测类型：
     • Jailbreak：DAN、角色代理等
     • Persona Override：虚构的 AI 身份
     • Indirect Prompt Injection：隐晦的指令污染
   - 工作模式：
     • 演示模式：返回预编成的脚本响应（100% 稳定）
     • 实时模式：调用 Anthropic Claude API，用严格 system prompt
                强制 LLM 引用原文证据，防止幻觉

【单个智能体的生命周期】

  Packet 来临 → 调用 analyse(packet)【入口，BaseAgent 提供】
  → 记录开始时间，打印日志
  → 调用 _analyse()【子类实现】
  → 返回 AuditResult：威胁分类 + 置信度 + 证据 + 理由
  → 反幻觉校验：确认所有证据都在原文里
  → 如果校验失败 → 降置信度到 0（信号不可信）
  → 如果校验成功 → 保持原始置信度
  → 记录完成时间 → 返回给 Judge 层

【为什么要多个智能体？】

单个模型的问题：
  • Pattern Agent 只能看表面特征，看不到"魔鬼细节"
  • LLM Agent 有时会一本正经地胡说八道（幻觉）

组合方案的优势：
  • Pattern 发现特征层威胁 → 高精度、快速、无依赖
  • Context 深度理解意图 → 覆盖变体、越狱等新型攻击
  • Judge 加权汇总 → 融合两者优点，规避单一弱点

【扩展点】

如果要再加新的智能体（例如 RateLimitAgent、AnomalyAgent），只需：
  1. 在此文件夹新建 xxx_agent/agent.py
  2. 继承 BaseAgent
  3. 实现 _analyse() 方法
  4. 在 judge/consensus.py 的 _AGENTS 列表中注册
  5. 调整 AGENT_WEIGHTS 权重配置
"""
