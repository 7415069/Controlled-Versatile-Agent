# 受控百变智能体 (CVA) — Controlled Versatile Agent

基于《受控百变智能体架构白皮书》的完整 Python 实现。

## 核心思想

> 智能体是一个"逻辑归零"的标准化容器。它本身不具备任何业务逻辑，
> 其所有行为倾向（灵魂）和操作边界（枷锁）全部由启动时注入的"属性包"决定。

## 项目结构

```
cva/
├── cv-agent.py                    # 主入口
├── requirements.txt
├── core/
│   ├── manifest.py           # Role Manifest 加载与校验
│   ├── memory.py             # 持久化上下文记忆
│   ├── llm_adapter.py        # LiteLLM 适配层
│   ├── permissions.py        # 运行时权限白名单管理
│   ├── escalation.py         # 越权申请管理器（核心安全组件）
│   ├── shell.py              # 统一底座：主循环 + LLM 通信
│   └── audit.py              # 审计日志（JSONL 追加写入）
├── tools/
│   └── catalog.py            # 8 个原子工具实现
└── roles/
    ├── code-reviewer-v1.yaml # 代码审查员
    ├── dba-assistant-v1.yaml # DBA 助手
    └── sre-log-analyst-v1.yaml # SRE 日志分析
```

## 快速开始

### 1. 安装依赖

```bash
pip install -r requirements.txt
```

### 2. 设置 API Key

```bash
export ANTHROPIC_API_KEY=your_api_key_here
```

### 3. 启动 Agent

```bash
# 代码审查员
python cva.py --manifest roles/code-reviewer-v1.yaml

# DBA 助手
python cva.py --manifest roles/dba-assistant-v1.yaml

# SRE 日志分析
python cva.py --manifest roles/sre-log-analyst-v1.yaml

# 指定模型和日志目录
python cva.py --manifest roles/code-reviewer-v1.yaml \
              --model claude-opus-4-5 \
              --log-dir ./audit-logs \
              --max-iterations 50
```

## 架构三要素

### 1. 统一底座（Universal Shell）
`core/shell.py` — 唯一的 Python 运行时，零业务偏见。负责：
- LLM API 通信（流式支持）
- Tool Call 解析与分发
- 对话历史上下文管理
- 审计日志写入

### 2. 属性配置包（Role Manifest）
`roles/*.yaml` — 定义角色灵魂与枷锁：

```yaml
role_name: code-reviewer-v1
identity_prompt: |
  你是一位专业的代码审查员...
init_permissions:
  read: ["./src/**", "./tests/**"]
  write: []
  shell: ["git log", "git diff"]
capabilities:
  - list_directory
  - read_file
  - ask_human
escalation_policy:
  auto_deny_patterns: ["/etc/**", "~/.ssh/**"]
  timeout_seconds: 120
```

### 3. 人类导师（Human Supervisor）
运行时通过控制台交互对越权申请进行裁定：

```
═══════════════════════════════════════════════════════
⚠️  [CVA 权限申请] — 需要您的授权
═══════════════════════════════════════════════════════
  申请 ID   : 550e8400-e29b-41d4-a716-446655440000
  工具      : read_file
  申请路径  : ./config/database.yaml
  权限类型  : read
  申请理由  : 需要读取数据库配置以分析连接池设置
───────────────────────────────────────────────────────
  [y] 批准    [n] 拒绝    [m] 修改路径后批准
───────────────────────────────────────────────────────
  请输入选项 (超时 120s 自动拒绝): 
```

## 自定义角色

创建新的 YAML 文件即可定义任意角色：

```yaml
role_name: my-custom-agent
version: "1.0"
identity_prompt: |
  你是一个...（描述角色和行为准则）
init_permissions:
  read: ["./data/**"]
  write: ["./output/**"]
  shell: []
capabilities:
  - list_directory
  - read_file
  - write_file
  - ask_human
escalation_policy:
  auto_deny_patterns: ["/etc/**", "~/.ssh/**"]
  notify_channel: console
  timeout_seconds: 180
```

## 支持的工具

| 工具名 | 说明 | 权限类型 |
|--------|------|----------|
| `list_directory` | 列出目录内容 | read |
| `read_file` | 读取文件内容 | read |
| `write_file` | 覆盖写入文件 | write |
| `append_file` | 追加写入文件 | write |
| `run_shell` | 执行 Shell 命令 | shell |
| `ask_human` | 向人类导师提问 | 无需权限 |
| `search_files` | 搜索文件名或内容 | read |
| `http_request` | 发起 HTTP 请求 | shell（URL前缀） |

## 审计日志

所有操作以 JSONL 格式写入 `audit-logs/` 目录：

```jsonl
{"timestamp":"2026-03-02T10:00:00Z","instance_id":"550e8400","role_name":"code-reviewer-v1","event_type":"AGENT_START",...}
{"timestamp":"2026-03-02T10:00:05Z","instance_id":"550e8400","event_type":"TOOL_CALL","tool_name":"list_directory",...}
{"timestamp":"2026-03-02T10:00:10Z","instance_id":"550e8400","event_type":"ESCALATION_REQUEST","requested_path":"./config",...}
{"timestamp":"2026-03-02T10:00:15Z","instance_id":"550e8400","event_type":"ESCALATION_APPROVED","approved_paths":["./config"],...}
```

## 安全设计

- **路径穿越防护**：所有路径调用 `os.path.realpath` 规范化后再比对白名单
- **Shell 注入防护**：`run_shell` 使用列表参数，禁止 `shell=True`
- **自动黑名单**：`auto_deny_patterns` 无需人类参与直接拒绝高危路径
- **超时保护**：越权申请默认 300s 超时后自动拒绝
- **最大迭代限制**：防止 LLM 无限循环消耗资源
