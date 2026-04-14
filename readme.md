# SentinelAgent (AIWAF)

SentinelAgent 是一个面向 LLM 场景的**多代理 AI 防火墙**，采用 1+N+1 三层架构，能够实时检测 SQL 注入、XSS、越狱攻击、提示词注入等多种威胁，并将每次审计结果持久化到 SQLite 数据库，通过 Admin Dashboard 可视化展示。

```
HTTP 流量
    ↓
[Layer 1]  Gateway        — 接收、标准化流量，写入审计日志
    ↓
[Layer N]  Expert Agents  — PatternAgent（正则）+ ContextAgent（DeepSeek LLM）并行
    ↓
[Layer 1]  Judge          — 加权聚合，输出 ALLOW / QUARANTINE / BLOCK
```

---

## 功能特性

### 核心检测

- **多代理并发审计** — PatternAgent 与 ContextAgent 通过 `asyncio.gather` 真正并行执行
- **反幻觉证据链** — 所有非良性判定要求 evidence 必须是 payload 的逐字子串，Pydantic 双层校验
- **共识裁决机制** — 基于权重（Pattern:1.0 / Context:1.2）和阈值（≥0.70 BLOCK / ≥0.45 QUARANTINE）输出最终动作
- **Safe-Pass 优雅降级** — ContextAgent 调用失败时以 BENIGN+confidence=0.0 回退，PatternAgent 独立支撑流水线

### 威胁覆盖

| 威胁类型 | 检测方式 |
|----------|----------|
| SQL 注入 | 正则（注释截断、恒真条件、UNION SELECT、堆叠查询）+ LLM 语义 |
| XSS | 正则（script 标签、事件处理器、javascript: 协议）|
| 提示词注入 | 正则 + LLM（指令劫持、角色混淆）|
| 越狱攻击 | LLM 语义（DAN、虚构框架、策略覆盖）|
| 数据外泄 | LLM 语义 |
| 权限提升 | LLM 语义 |

### 持久化审计日志

- SQLite 数据库（`sentinel_audit.db`），`aiosqlite` 异步写入，不阻塞检测主路径
- 每条记录包含：时间戳（UTC，展示转北京时间）、来源 IP、原始载荷、风险分、完整推理、最终动作
- 支持通过 `DB_PATH` 环境变量指定服务器上的绝对路径

### Admin Dashboard（后台管理）

访问路径：启动 Streamlit 后在侧边栏点击 **Admin Dashboard**

- **登录保护** — 凭据来自 `.env`（`ADMIN_USERNAME` / `ADMIN_PASSWORD`），`st.stop()` 硬拦截未授权访问
- **实时指标** — 累计请求数 / 拦截率 / 平均风险分 / 系统状态（30 秒缓存，1 vCPU 友好）
- **攻击类型分布图** — Plotly 交互式横向柱状图（SQL 注入 / XSS / 越狱 / 提示词注入等）
- **审计日志浏览器** — 最近 50 条，含北京时间 / 动作徽章 / 风险分 / 来源 IP / 攻击类型 / 载荷摘要
- **证据检查器** — 下拉选择任意日志 ID，展示 DeepSeek 完整推理（色彩区分 BLOCK/QUARANTINE/PASS）+ 原始载荷

### 演示面板

- **双栏叙事 UI** — 左栏"入侵者"打字机动画，右栏"防守者"实时会诊
- **逐步可视化** — PatternAgent → ContextAgent（等待动画）→ Judge 裁决，完整展示推理过程
- **三种测试载荷** — SQL 注入 / 越狱攻击 / 正常请求，每次攻击结果自动写入审计数据库

---

## 项目结构

```text
AIWAF/
├── agents/
│   ├── base_agent.py                # 抽象基类 + 证据锚定反幻觉校验
│   ├── pattern_agent/agent.py       # 规则专家（9 条正则签名）
│   └── context_agent/agent.py       # 语义专家（DeepSeek API）
├── gateway/
│   ├── main.py                      # FastAPI 应用入口 + lifespan DB 初始化
│   └── router.py                    # /api/v1/audit 路由（含审计日志写入）
├── judge/
│   └── consensus.py                 # 加权聚合 + 共识裁决
├── shared/
│   ├── schemas.py                   # 全局数据契约（Pydantic v2，frozen）
│   ├── database.py                  # SQLite 持久化层（aiosqlite）
│   └── llm_client.py                # 多 LLM 提供商统一客户端
├── frontend/
│   ├── app.py                       # Streamlit 双栏演示界面（含攻击日志写入）
│   ├── styles.css                   # 共享样式（深色主题）
│   └── 水晶盾.png                   # 品牌 logo
├── pages/
│   └── Admin_Dashboard.py           # 后台管理仪表盘（登录保护）
├── data/
│   └── mock_attack_stream.json      # 演示流量样本（3 条）
├── tests/
│   └── test_schemas.py              # Pydantic 契约测试
├── test_pipeline.py                 # 全流程端到端冒烟测试（9 步）
├── demo_runner.py                   # 命令行演示脚本
├── sentinel_audit.db                # SQLite 审计数据库（运行时生成）
├── .env.example                     # 环境变量模板
├── requirements.txt
└── pyproject.toml
```

---

## 运行环境

- Python 3.11+（已在 3.14 验证）
- Windows / macOS / Linux 均可
- 最低配置：1 vCPU / 1 GB RAM（服务器部署）

---

## 快速开始

### 1. 安装依赖

```bash
pip install -r requirements.txt
```

或使用 Poetry：

```bash
poetry install
```

### 2. 配置环境变量

```bash
cp .env.example .env
```

编辑 `.env`，按需填写：

```ini
# LLM 提供商（deepseek / openai / anthropic）
LLM_PROVIDER=deepseek
DEEPSEEK_API_KEY=sk-...

# 后台管理登录凭据（部署前务必修改）
ADMIN_USERNAME=admin
ADMIN_PASSWORD=your_password_here

# 数据库路径（留空 = 项目根目录；服务器部署建议填绝对路径）
DB_PATH=
# DB_PATH=/opt/sentinel/data/sentinel_audit.db
```

### 3. 启动演示前端

```bash
streamlit run frontend/app.py
```

浏览器打开 `http://localhost:8501`，即可使用双栏攻击演示面板。

### 4. 启动后台管理（独立端口）

```bash
streamlit run pages/Admin_Dashboard.py --server.port 8502
```

浏览器打开 `http://localhost:8502`，使用 `.env` 中配置的账号密码登录。

> 两个面板需要**分别启动**，共用同一个 `sentinel_audit.db` 数据库。
> 演示面板产生的攻击记录会实时同步到后台管理（刷新或等待 30 秒缓存到期）。

### 4. 启动 API 网关（可选）

```bash
uvicorn gateway.main:app --reload --host 0.0.0.0 --port 8000
```

- 健康检查：`http://localhost:8000/health`
- OpenAPI 文档：`http://localhost:8000/docs`

### 5. 运行全流程测试

```bash
python test_pipeline.py
```

期望输出：`ALL 9 STEPS PASSED -- pipeline fully operational`

---

## API 参考

### POST `/api/v1/intercept` — 通用拦截

```bash
curl -X POST http://localhost:8000/api/v1/intercept \
  -H "Content-Type: application/json" \
  -d '{"text": "SELECT * FROM users WHERE id=1 OR 1=1--"}'
```

### POST `/api/v1/audit` — 预构造 Packet 审计

请求体需符合 `shared/schemas.py` 中的 `Packet` 结构（含 `PacketMetadata`）。

### GET `/api/v1/demo/stream` — 获取演示流量

返回 `data/mock_attack_stream.json` 内容。

---

## 核心设计

### 反幻觉双层防护

```
Layer 1 — Pydantic validator
  非 BENIGN 威胁必须携带 evidence[]（否则抛 ValidationError）

Layer 2 — BaseAgent._validate_evidence_anchor()
  evidence 中每个字符串必须是 raw_text 的逐字子串
  验证失败 → confidence 降为 0.0，不影响流水线可用性
```

### 共识算法

```
AGENT_WEIGHTS = { pattern_agent_v1: 1.0, context_agent_v1: 1.2 }
BLOCK_THRESHOLD     = 0.70
QUARANTINE_THRESHOLD = 0.45

加权平均 confidence → 与阈值比较 → BLOCK / QUARANTINE / ALLOW
```

### 数据流

```
Packet(raw_text, metadata)
  → [PatternAgent || ContextAgent]  并行
  → [AuditResult, AuditResult]
  → Judge.build_verdict()
  → ConsensusVerdict
  → log_request() → sentinel_audit.db
  → HTTP Response
```

---

## 测试

```bash
# 单元测试（Pydantic 契约）
pytest -v

# 全流程冒烟测试（含真实 DeepSeek 调用 + DB 读写）
python test_pipeline.py
```

---

## 上线部署建议

- **不要提交 `.env`** — 已加入 `.gitignore`，通过服务器环境变量或 Secrets 注入
- **修改默认密码** — `ADMIN_PASSWORD` 在上线前必须修改
- **指定 DB 路径** — 设置 `DB_PATH=/opt/sentinel/data/sentinel_audit.db`，避免数据库随代码目录漂移
- **固定 venv** — 始终用 `.venv/Scripts/streamlit` 启动，防止系统 Python 缺包导致 Safe-Pass 降级

---

## 后续扩展方向

- 增加更多 Expert Agent（行为基线、重放检测、速率限制）
- 将阈值和权重外置到配置文件，支持热更新
- Admin Dashboard 增加时间范围过滤和 CSV 导出
- 引入 WebSocket 实现审计日志实时推送
- 增加端到端压测与性能基准报告
