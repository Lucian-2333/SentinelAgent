# gateway/__init__.py
"""
gateway/ 文件夹 — 流量拦截网关层（Layer 1）
═════════════════════════════════════════════════════════════════════════════

【职责概述】
Gateway 是系统唯一 HTTP 入口，负责把外部请求转换为内部统一契约，
并把最终判决结果返回给调用方。

【当前文件组成】

gateway/__init__.py ← 当前模块说明文件

gateway/main.py
  - FastAPI 应用入口。
  - 提供 /health、/api/v1/demo/stream、/api/v1/intercept 三类端点。
  - 在 lifespan 启动阶段调用 shared.database.init_db() 初始化审计表。
  - /api/v1/intercept 完成：请求解析 -> Packet 组装 -> 共识裁决 ->
    写入审计日志（失败不阻塞响应）。

gateway/router.py
  - 提供 /api/v1/audit 路由（接收完整 Packet，返回 ConsensusVerdict）。
  - 与 main.py 分离，保持启动逻辑与业务路由解耦。

【请求处理要点】

1. /api/v1/intercept
   - 输入是通用 JSON（至少包含 text）。
   - 由网关构建 Packet 与 PacketMetadata。
   - 同步返回共识结果，并尝试落审计日志。

2. /api/v1/audit
   - 输入是已成型 Packet。
   - 适合内部链路或演示脚本直接调用。

【当前配置说明】

- CORS 允许所有来源（演示友好，生产应收紧）。
- 日志写入是“尽力而为”策略：写库失败不会影响主响应。
"""
