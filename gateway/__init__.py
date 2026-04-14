# gateway/__init__.py
"""
gateway/ 文件夹 — 流量拦截网关层（Layer 1）
═════════════════════════════════════════════════════════════════════════════

【职责概述】
Gateway 是 1+N+1 架构的最外层（第一层），负责：
  1. 接收来自客户端的原始 HTTP 请求（JSON 格式）
  2. 将请求体标准化为 Packet 对象（不可变数据结构）
  3. 给每个 Packet 打上元数据印章（来源、IP、时间戳等）
  4. 将 Packet 转发给审计管道（Judge 层）
  5. 返回最终判决（ConsensusVerdict）给客户端

简单来说：Gateway 是"厚度 1 毫米的中间层"，隔离了客户端和审计逻辑。

【文件组成】

gateway/__init__.py ← 当前模块说明文件

gateway/main.py
  - FastAPI 应用启动和配置文件
  - 职责：
    ✓ 创建 FastAPI 应用、启用 CORS 跨域资源共享
    ✓ 挂载生命周期钩子（启动/关闭日志）
    ✓ 注册 health 检查端点（健康探针）
    ✓ 注册 intercept 端点（核心审计入口）
    ✓ 注册 demo stream 端点（演示数据获取）
  
  - 关键端点详解：

    GET /health
      用途：健康检查（负载均衡器、监控工具用）
      返回：{"status": "ok", "service": "sentinel-gateway"}
      作用：告诉外界系统还活着

    GET /api/v1/demo/stream
      用途：获取预编脚本演示数据
      返回：JSON 数组，每个元素是一个预设攻击样本
      目的：前端可以驱动演示而不需要真实攻击者

    POST /api/v1/intercept     ← 最重要的端点
      用途：审计任意 JSON 有效负载
      请求体格式示例：
        {
          "text": "admin' -- password = 'anything'",
          "source": "human_user",
          "extra": {}
        }
      text 字段含义：要被审计的内容（必填、非空）
      source 字段：来源类型（可选，默认 API_CALL）
      
      返回：ConsensusVerdict JSON 对象
        {
          "packet_id": "uuid-string",
          "status": "allow"|"block"|"quarantine"|"pending",
          "dominant_threat": "sql_injection"|"benign"|...,
          "aggregate_confidence": 0.92,
          "contributing_agents": ["pattern_agent_v1"],
          "dissenting_agents": [],
          "judge_reasoning": "共识理由文本...",
          "decided_at": "ISO 8601 时间戳",
          "raw_audits": [各个 Agent 的原始审计结果]
        }
      
      处理流程：
        1. 解析 JSON body（失败返回 400）
        2. 提取 text 字段（空值返回 422）
        3. 构造 PacketMetadata（从 HTTP 请求获取 IP、UA）
        4. 创建 Packet（生成 UUID 作为 packet_id）
        5. 调用 run_consensus_pipeline(packet)
        6. 返回 ConsensusVerdict JSON

gateway/router.py
  - API 路由定义与组织
  - 当前只有一个路由组（audit_router）
  - 选择分离 router 是为了：
    ✓ 让 main.py 代码保持小而精（关注启动逻辑）
    ✓ 支持将来可能的多版本 API（/v1、/v2、...）
    ✓ 便于单独对某个路由组进行单元测试

  - 路由端点细节：

    POST /api/v1/audit
      用途：审计一个已经组装好的 Packet 对象
      入参：Packet JSON（包含所有必填字段）
      返回：ConsensusVerdict JSON
      
      用途场景：
        • 多步审计链（上一步输出是下一步输入）
        • 演示脚本调用（跳过 gateway 的 raw text → Packet 转换）
        • 内部系统间通讯（一个 Agent 调另一个 Agent）

【网关为什么必要？】

如果简单地直接调 Judge，会有问题：
  ✗ 每个调用者要自己创建 Packet 和元数据 → 重复代码
  ✗ 元数据来源不安全 → 客户端可以伪造 IP 地址
  ✗ 错误处理分散 → 同样的 400 错误在多处出现
  ✗ CORS/认证/限流处理混乱 → 得在逻辑层处理，职责不清

有了网关：
  ✓ 唯一的入口 → 统一认证、限流、日志
  ✓ 受信的 IP/UA 来源 → 从 HTTP 层取，客户端伪造难
  ✓ 错误处理集中 → HTTP 状态码语义明确
  ✓ 未来好升级 → 要加 API 键、签名校验，只需改网关
  ✓ 性能优化集中 → 缓存、速率限制都在网关层

【错误处理策略】

400 Bad Request  — JSON 格式错误、无法解析
422 Unprocessable Entity — text 字段缺失或为空
500 Internal Server Error — Judge 管道异常（表示系统故障）

关键原则：错误消息应该对开发者有帮助但不泄露内部细节。

【为什么用 FastAPI？】

  • asyncio 原生支持 → 适合并发处理多个审计请求
  • Pydantic 集成 → 自动 JSON schema 校验
  • 文档自动生成 → Swagger UI（开发便利）
  • 极简学习曲线 → 从 Flask 迁移成本极低
  • 性能优异 → 毫秒级响应

【CORS（跨源资源共享）】

当前配置：allow_origins=["*"]
  ℹ️  演示环境可接受（任何前端都可调用）
  ⚠️  生产环境应改为白名单，如：
       ["https://frontend.example.com", "https://admin.example.com"]

【启动/关闭生命周期】

启动时日志："🛡️  SentinelAgent Gateway starting up…"
关闭时日志："🛡️  SentinelAgent Gateway shutting down."
便于：
  • 监控系统识别重启事件
  • 日志聚合器设置警报规则
  • 运维人员理解系统状态变化

【未来扩展点】

1. 加入 API 键认证
   - 每次请求检查 X-API-Key 头
   - 维护 API 键到客户端的映射表

2. 加入速率限制
   - 每个 IP/API 键只允许 N 个请求/分钟
   - 超限返回 429 Too Many Requests

3. 加入请求签名
   - 客户端用密钥对请求签名
   - 网关验证签名，防止篡改

4. 加入审计日志
   - 所有请求/响应写入数据库
   - 便于事后审查和合规性检查
"""
