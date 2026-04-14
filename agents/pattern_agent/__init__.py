# agents/pattern_agent/__init__.py
"""
agents/pattern_agent/ — 规则签名分析智能体
═════════════════════════════════════════════════════════════════════════════

【模块职责】
PatternAgent 是多智能体中的"规则专家"。它负责通过预编译的正则表达式
快速识别已知的攻击特征，是防火墙的"第一道防线"。

特点：
  ✓ 零外部依赖 — 无需 LLM、无网络调用、无 API 费用
  ✓ 高确定性 — 同样输入永远同样输出（类似哈希函数）
  ✓ 高速率 — 毫秒级响应（相比 LLM 的 500ms+）
  ✓ 高精度 — 规则都是从实战中提炼的
  ✓ 易维护 — 规则都用注释清晰标注

【文件说明】

pattern_agent/agent.py
  - PatternRule 冻结数据类
    • name: 规则名（便于识别和调试）
    • pattern: 编译的正则表达式对象
    • threat_category: 威胁分类（从 ThreatCategory 枚举选）
    • base_confidence: 基础置信度 [0.0, 1.0]（规则本身的"准确性"）
    • description: 人类可读的规则说明

  - PatternAgent 类
    • 核心方法：_analyse(packet) → AuditResult
    • 逻辑：对输入文本逐个应用所有规则，收集所有命中
    • 置信度选择：取最高置信度的规则作为主判定
    • 证据汇总：收集所有规则的匹配片段，去重，上限 10 个
    • 理由生成：列出所有触发的规则及其描述

【规则库详解】

═══ SQL Injection （SQL 注入） ═══

1. sqli_comment_bypass（注释绕过）
   正则：(--|#|/\*).{0,80}(select|insert|...)
   触发例子：admin' -- password = ...
   原理：用注释符 -- 或 # 或 /* 截断 SQL，忽略后续条件
   置信度：0.93（非常高，几乎肯定是 SQLi）
   现实案例：用户名字段输入 "admin' --" 绕过密码检查

2. sqli_tautology（恒真条件）
   正则：(or|and)\s+['"...]\w+['"...]\s*=\s*['"...]\w+['"...]
   触发例子：OR 1=1 或 AND 'x'='x'
   原理：永真的逻辑条件，绕过 WHERE 逻辑
   置信度：0.80
   现实案例：WHERE username='admin' OR 1=1 → 返回所有用户

3. sqli_union_select（UNION 查询泄露）
   正则：union\s+(all\s+)?select
   触发例子：' UNION SELECT password FROM users --
   原理：并联多个查询，用来数据窃取
   置信度：0.95（几乎肯定是 SQLi，误报极少）
   现实案例：UNION 查询窃取其他表的敏感数据

4. sqli_stacked_queries（堆积查询）
   正则：;\s*(select|insert|update|drop|...)
   触发例子：'; DROP TABLE users --
   原理：用分号分隔多条 SQL 语句，一并执行
   置信度：0.88
   现实案例：一个字段注入多条语句，造成系统破坏

═══ Cross-Site Scripting （XSS 跨站脚本） ═══

1. xss_script_tag（script 标签注入）
   正则：<\s*script[^>]*>
   触发例子：<script>alert('xss')</script>
   原理：直接注入 script 标签，在浏览器执行
   置信度：0.90
   现实案例：评论框输入 <script>，触发客户端 JavaScript

2. xss_event_handler（事件处理器注入）
   正则：on(load|click|mouseover|error|focus)\s*=
   触发例子：<img onerror="alert(1)">
   原理：HTML 标签上的事件处理器执行 JavaScript
   置信度：0.85
   现实案例：图片加载失败时触发恶意代码

3. xss_javascript_uri（javascript: 伪协议）
   正则：javascript\s*:
   触发例子：<a href="javascript:void(0)">点我</a>
   原理：javascript: 伪 URI 协议执行代码
   置信度：0.88
   现实案例：超链接点击时执行恶意脚本

═══ Prompt Injection （提词注入） ═══

1. prompt_injection_ignore_prev（忽略前文指令）
   正则：ignore\s+(all\s+)?(previous|prior|...)\s+(instructions?|prompts?)
   触发例子："忽略所有前面的指令" 或 "ignore previous context"
   原理：直接指令 AI 忽略系统规则
   置信度：0.82
   现实案例：攻击者让 ChatBot 无视安全规则

2. prompt_injection_new_instructions（替换系统指令）
   正则：(your\s+new\s+instructions?|new\s+system\s+prompt|forget\s+your)
   触发例子："你的新指令是..." 或 "forget your training"
   原理：尝试替换 AI 的系统级指令
   置信度：0.78
   现实案例：攻击者试图让 AI 改变行为模式

【工作流程】

  输入 Packet
       ↓
  对每条规则 R 逐个执行：
    ↓
    用 R.pattern 在 packet.raw_text 上执行 findall()
    ↓
    如果匹配 → 加入 fired 列表（规则 + 匹配片段）
  ↓ （规则循环结束）
  ↓
  if fired 列表为空（无任何规则匹配）：
    → 返回 BENIGN 结果（无威胁）
  else 有规则匹配：
    → 选置信度最高的规则作为主导
    → 汇总所有规则的匹配片段作证据（去重、上限 10 个）
    → 返回 AuditResult：
        - threat_category = 主导规则的威胁类型
        - confidence = 主导规则的 base_confidence
        - reasoning = 所有触发规则名 + 描述
        - evidence = 所有匹配片段（去重）
        - analysed_at = 当前时间戳

【为什么多规则时选最高置信度？】

假设一个攻击同时触发：
  • sqli_union_select (0.95)
  • sqli_comment_bypass (0.93)

我们选择 UNION SELECT 因为它置信度更高。
理由：
  • UNION SELECT 是明确的数据泄露企图，几乎没有误报
  • 两者都指向 SQLi，差异只在细节，主导判定一致
  • 选高置信度的可以降低误报率

但是 Judge 层会看到所有触发的规则，所以完整信息不丢失。

【为什么是正则而不是 NLP？】

SQL/XSS 的超高表面特征性 → 正则最优
  • 特征模式非常明确（固定的关键字、符号）
  • 不需要语义理解，只需字面匹配
  • 毫秒级速度，响应及时
  • 零误报（如果规则写得好）
  • 离线执行，无外部依赖

而 Prompt Injection 倒是需要 LLM 来理解意图 → 用 ContextAgent

【规则维护与回归】

后续建议添加更多规则来覆盖：
  • SQLi 变体（编码混淆、延时注入、布尔盲注等）
  • XSS 变体（DOM XSS、Stored XSS、blind XSS 等）
  • 其他威胁（CSRF token bypass、XXE、path traversal 等）
  • WAF 绕过技巧（大小写混合、编码逃逸、符号变形等）

需要建立规则回归测试套件，确保规则永不退化。

【性能优化**】

当前实现已经很快（毫秒级），如果还要更快：
  • 规则已编译缓存（不是每次编译正则）
  • 可按文件类型分组（JSON 用不着 SQL 规则）
  • 可加优先级，先跑高精度规则，快速短路

"""
