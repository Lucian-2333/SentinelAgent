# tests/__init__.py
"""
tests/ 文件夹 — 单元测试与集成测试
═════════════════════════════════════════════════════════════════════════════

【职责概述】
Tests 文件夹负责验证系统的正确性和鲁棒性，确保：
  ✓ 各模块独立工作正常（单元测试）
  ✓ 模块间集成协作无缺（集成测试）
  ✓ 反幻觉约束被强制（契约测试）
  ✓ 代码改动不产生回归（回归测试）

【测试框架】

工具：pytest + pytest-asyncio + httpx
  • pytest — 测试运行器和断言库
  • pytest-asyncio — 异步测试支持（async def test_xxx()）
  • httpx — HTTP 客户端（FastAPI TestClient 依赖）

运行命令：
  pytest tests/ -v              # 详细输出
  pytest tests/test_schemas.py # 仅跑某个文件
  pytest -k "pattern"          # 仅跑名称包含 pattern 的测试

【当前测试覆盖】

tests/test_schemas.py
  目标：验证 shared/schemas.py 的数据合约
  内容包括：
    ✓ test_packet_is_immutable — 验证 Packet 不能被改（frozen）
    ✓ test_packet_rejects_empty_text — 验证空 text 要被拒绝
    ✓ test_packet_auto_generates_id — 验证 UUID 自动生成
    ✓ test_audit_result_benign_needs_no_evidence — Benign 可以无证据
    ✓ test_audit_result_threat_requires_evidence — 非 Benign 必须有证据
    ✓ test_audit_result_confidence_bounds — 验证置信度 [0,1] 范围
    ✓ test_valid_threat_audit_result — 验证合法威胁结果
    ✓ test_consensus_verdict_structure — 验证 ConsensusVerdict 结构
  
  最关键测试：
    test_audit_result_threat_requires_evidence() —— 反幻觉约束的第一关
      确保 Pydantic validator 真的在工作
      任何人想偷偷创建一个 SQL_INJECTION 结果却不提证据 → 立即失败

【缺失的测试（待补）】

1. 网关集成测试（Gateway Integration Tests）
   ────────────────────────────────────────
   应该测试的场景：
     ✓ POST /api/v1/intercept 正常请求
     ✓ POST /api/v1/intercept 缺少 text 字段 → 返回 422
     ✓ POST /api/v1/intercept 空 text → 返回 422
     ✓ POST /api/v1/intercept 无效 JSON → 返回 400
     ✓ GET /health 返回 200 OK
     ✓ GET /api/v1/demo/stream 返回 mock 数据
   
   为什么重要？
     • 验证 HTTP 接口边界
     • 确保错误消息用户友好
     • 防止网关层的漏洞

2. Agent 单元测试（Agent Unit Tests）
   ───────────────────────────────────
   应该测试的场景：
     ✓ PatternAgent.analyse() 返回合法 AuditResult
     ✓ PatternAgent 规则命中回归
       - pkt with "admin'--" → 返回 SQL_INJECTION
       - pkt with "<script>" → 返回 XSS
       - pkt with "normal text" → 返回 BENIGN
     ✓ ContextAgent 脚本模式返回预期结果
     ✓ BaseAgent._validate_evidence_anchor() 生效
       - 如果 Agent 编造证据 → confidence 降到 0
   
   为什么重要？
     • 每个 Agent 必须单独验证
     • 规则库改动后要回归测试
     • 调试 Agent 行为

3. Judge 共识算法测试（Consensus Algorithm Tests）
   ──────────────────────────────────────────────────
   应该测试的场景：
     ✓ 仅 PatternAgent 投 SQLi(0.93) → 预期 status=BLOCK
     ✓ 仅 ContextAgent 投 Benign(0.1) → 预期 status=ALLOW
     ✓ Pattern投 SQLi(0.93), Context投 Benign(0.1) → 主导是 SQLi
       （验证各自权重，生成对的 aggregate_confidence）
     ✓ 分歧检测
       - 两个 Agent 意见相反，dissenting_agents 不为空
     ✓ 置信度阈值验证
       - aggregate_confidence = 0.75 → status = BLOCK
       - aggregate_confidence = 0.50 → status = QUARANTINE
       - aggregate_confidence = 0.30 → status = ALLOW
   
   为什么重要？
     • Judge 的共识算法是系统的核心逻辑
     • 任何改阈值都要配套改测试
     • 防止因权重调整产生意外行为

4. 演示脚本测试（Demo Runner Tests）
   ─────────────────────────────────
   应该测试的场景：
     ✓ demo_runner.py 能加载 mock_attack_stream.json
     ✓ json 中每个 packet 都能通过审计管道
     ✓ 输出包含颜色代码和预期信息
     ✓ 无异常抛出（全程流畅运行）
   
   为什么重要？
     • 演示脚本是黑客松的"门面"
     • 演示时如果崩溃 = 直接失分
     • 要确保 100% 稳定可靠

5. 端到端集成测试（End-to-End Integration Tests）
   ──────────────────────────────────────────────────
   测试整个流程一条龙：
     1. 启动网关服务
     2. 发送多种 payload（SQLi、XSS、合法、...）
     3. 验证每个返回的 ConsensusVerdict
     4. 检查 Judge 的分析过程
     5. 性能测量（响应时间、吞吐量）
   
   为什么重要？
     • 验证系统在真实条件下完整运行
     • 跨模块交互的验证
     • 性能基准测试（响应时间、吞吐量）

【测试编写风格】

原则：
  1. 一个测试函数 = 一个行为验证
     ✗ 不要在一个 test 里验证 10 个东西
     ✓ test_foo_does_x(), test_foo_does_y(), test_foo_does_z()

  2. 名字要明确
     ✗ def test_agent():
     ✓ def test_pattern_agent_detects_sqli_comment_bypass():

  3. 用 fixtures 共享测试数据
     @pytest.fixture
     def benign_packet() -> Packet:
         return Packet(raw_text="Hello", ...)

  4. 异步测试要用 async
     async def test_context_agent_analyzes_packet():
         result = await agent.analyse(packet)
         assert result.threat_category == ThreatCategory.BENIGN

  5. 用 pytest.raises() 验证异常
     with pytest.raises(ValidationError, match="evidence"):
         AuditResult(..., evidence=[])  # 该失败的一定失败

【CI/CD 集成】

未来可以配置：
  • GitHub Actions / GitLab CI — 每次 push 都跑测试
  • 覆盖率检查 — 新代码的测试覆盖率不低于 80%
  • 性能基准 — 防止回归导致 API 响应缓慢

【测试数据管理】

演示 Payload：
  文件：data/mock_attack_stream.json
  用途：演示和测试的标准样本
  可以扩展新的测试样本

【运行测试】

本地开发：
  cd /path/to/project
  pytest -v                          # 跑所有测试
  pytest tests/test_schemas.py -v    # 跑单个文件
  pytest --tb=short                  # 简化回溯信息

CI 环境：
  mkdir -p .github/workflows
  编写 test.yml，定义测试流程
  每次 PR 前自动跑测试
"""
