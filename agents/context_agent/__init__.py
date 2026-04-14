# agents/context_agent/__init__.py
"""
agents/context_agent/ — 语义意图分析智能体
═════════════════════════════════════════════════════════════════════════════

【模块职责】
ContextAgent 是多智能体中的"语义专家"。它负责通过 LLM（如 Claude）理解
用户输入的"真实意图"，识别规则无法捕捉的攻击，特别是：
  • 越狱（Jailbreak）— 试图绕过 AI 安全准则的多层技巧
  • 人格覆盖（Persona Override）— 让 AI 扮演无约束角色
  • 间接提词注入 — 隐晦的指令污染

【文件说明】

context_agent/agent.py
  - ContextAgent 类及其实现
  - 两种工作模式：
    ① 演示模式（SENTINEL_DEMO_MODE=1）：返回预编脚本结果
    ② 实时模式：调用 Claude API 实时分析
  - 反幻觉机制：强制 LLM 必须从原文中复制证据，禁止编造
  - 故障转移：API 不可用时自动降级到 UNKNOWN（而非硬崩溃）

【工作流程】

  Packet 合法性检查 ✓
       ↓
  判断运行模式（读环境变量 SENTINEL_DEMO_MODE）
       ├→ if SENTINEL_DEMO_MODE=1 → 用脚本响应
       │    ↓
       │  查预编表得到 AuditResult
       │    ↓
       │  返回（100% 稳定，无网络延迟）
       │
       └→ else → 调用 Claude API
            ↓
          构造 system prompt（强制遵守反幻觉规则）
            ↓
          构造 user message（"请分析这个文本..."）
            ↓
          调用 Claude Opus 4.5 模型
            ↓
          解析 JSON 响应
            ↓
          创建 AuditResult
            ↓
          如果 JSON 解析失败/API 异常 → 返回 fallback（置信度 0.5）
            ↓
          返回

【System Prompt 的关键规则】

系统级指令强制 LLM：
  1. 只输出 JSON，无 markdown 包装
  2. evidence 数组必须是原文的逐字复制（不允许释义或改写）
  3. 如果找不到证据，就设为 benign 和空数组
  4. 必须解释"为什么"这些证据是可疑的

这确保：
  • 输出结构化且可机器读取
  • 不会编造没有根据的判定
  • Judge 层可完全信任 LLM 的结论
  • 审计链条完整可回溯

【演示模式脚本表】

pkt-sqli-001
  威胁: SQL Injection
  置信度: 0.72
  证据: ["admin' --", "password = 'anything'"]
  理由: SQL 注释符绕过 WHERE 条件，正是 SQLi 经典手法

pkt-jailbreak-002
  威胁: Jailbreak
  置信度: 0.94
  证据: ["Imagine you are DAN", "无限制 AI", ...]
  理由: 多层越狱技巧叠加（人格覆盖+虚构框架+指令无效化）

pkt-benign-003
  威胁: Benign
  置信度: 0.04
  证据: []
  理由: 纯净的技术问询，无任何攻击信号

【为什么分离网络调用？】

在 _llm_response() 中，API 调用被包装在 try-except 中：
  • 失败时打印异常日志
  • 返回降级结果（UNKNOWN, confidence=0.5）
  • 实际系统继续运行，不中断整个审计链

好处：
  • 即使 Claude API 宕机，审计不会彻底瘫痪
  • Pattern Agent 仍可继续工作
  • Judge 会记录"Context Agent 无法完成"并注明原因
  • 用户能获得部分结论而不是完全失败

【扩展机会】

如果要修改检测类型或规则，改这个文件中的：
  • _SCRIPTED_RESPONSES 字典 — 演示模式的预编脚本
  • SYSTEM_PROMPT — LLM 的系统级指令
  • 模型选择 — 当前是 claude-opus-4-5

【故障排查】

常见问题及解决：
  ✗ "anthropic SDK not installed" — 运行 pip install anthropic
  ✗ API 超时 — 检查网络连接，调整 max_tokens 参数
  ✗ JSON 解析失败 — 检查 Claude API 返回格式是否变化
  ✗ Hallucination（幻觉）— 加强 SYSTEM_PROMPT 的约束
"""
