
# CVA - 受控百变智能体 (Controlled Versatile Agent)

**版本**：v3.5（Universal Shell v3.5 + 安全强化版）  
**状态**：生产就绪 · 安全审计通过 · Token 优化完成  

CVA 是一个**企业级、安全可控的多角色 LLM Agent 框架**，专为开发者、SRE、DBA、代码审查员等专业场景设计。它在赋予 LLM 强大工具能力的同时，严格执行权限管控、越权审批、审计追踪与资源优化，确保 Agent 行为始终在可信边界内。

---

## ✨ 核心特性

### 1. 分层安全防护体系
- **运行时权限管理**（PermissionChecker v4.0）：基于 `pathspec` 的 gitignore 风格白名单，支持 `!` 排除规则
- **风险分级越权审批**（EscalationManager v3.1）：
  - **LOW**：自动批准（只读安全目录）
  - **MEDIUM**：LLM 二次确认后自动批准
  - **HIGH**：必须人工审批（含 `execute_python_script`、危险 shell）
- **LLM 自省预审** + **重复申请自动通过** + **权限自动过期撤销**
- **自动拒绝黑名单**（`/etc/**`、`.env`、`.ssh` 等）

### 2. 结构化审计与可追溯性
- **每日滚动 JSONL 日志** + **自动轮转** + **大小限制**（100MB）+ **过期清理**（30 天）
- 记录每一次权限申请、审批决策、工具调用与风险分类
- 提供 `get_log_stats()` 接口实时监控日志占用

### 3. 智能上下文记忆（MemoryStore v2.2）
- **重要性标签规则引擎**（零 LLM 调用）：`ANCHOR` / `DECISION` / `PROCESS` / `NOISE`
- **智能脱水**：归档区折叠 + 文件内容 Skeleton（AST 解析 Python 类/函数）
- **增量 Token 估算 + 60 秒缓存**，默认预算 50,000 tokens
- **成对删除工具调用记录**，避免上下文膨胀

### 4. 高性能 LLM 适配层（LLMAdapter v3.2）
- LiteLLM 全模型支持 + 自动重试 + 错误分类
- 公开 `stats` 接口（调用次数、Token 消耗、错误分布）
- 请求长度校验（最大 250,000 字符输入）

### 5. 丰富工具集（13+ 内置工具）
| 工具                  | 用途                     | 安全级别 |
|-----------------------|--------------------------|----------|
| `list_directory`      | 目录浏览                 | LOW      |
| `get_project_summary` | 项目概览（含文件大小/行数）| LOW      |
| `read_file`           | 读取文件（限 30,000 字符）| LOW      |
| `write_file` / `append_file` | 安全写入              | MEDIUM   |
| `backup_file`         | 修改前自动备份           | MEDIUM   |
| `run_shell`           | 受控 Shell 执行          | HIGH     |
| `execute_python_script` | 沙盒 Python 执行      | HIGH     |
| `submit_plan`         | 任务状态机更新           | LOW      |
| `ask_human`           | 人工交互                 | MEDIUM   |
| `http_request`        | 外部 API 调用            | MEDIUM   |
| `find_symbol` / `get_file_skeleton` / `search_files` | 代码分析 | LOW |

---

## 📁 项目结构
```
CVA/
├── core/                  # 核心运行时（全部生产就绪）
│   ├── shell.py           # UniversalShell 主入口 v3.5
│   ├── permissions.py     # 权限管理 v4.0（pathspec）
│   ├── escalation.py      # 越权审批 v3.1
│   ├── memory.py          # 记忆优化 v2.2
│   ├── audit.py           # 审计日志 v2
│   ├── llm_adapter.py     # LLM 适配 v3.2
│   ├── manifest.py        # 角色配置加载
│   ├── tool.py            # 工具基类与注册表
│   └── logger.py
├── roles/                 # 预置角色模板
│   ├── developer-v1.yaml
│   ├── code-reviewer-sample-v1.yaml
│   ├── dba-assistant-sample-v1.yaml
│   └── sre-log-analyst-sample-v1.yaml
├── tests/                 # 完整测试套件（安全 + 性能 + 功能）
│   ├── test_security_fixes.py
│   ├── test_permissions.py
│   ├── test_performance.py
│   ├── test_token_optimization.py
│   └── test_universal_shell_capabilities.py
├── cv_agent.py            # 主文件
├── agent_workspace/       # Agent 工作目录（运行时生成）
├── audit-logs/            # 审计日志（每日滚动）
├── memory/                # 会话持久化
└── README.md              # 本文档
```

---

## 🚀 快速开始

### 1. 环境要求
- Python 3.10+
- 依赖（推荐使用 `requirements.txt`）：
  ```bash
  litellm
  pathspec
  pyyaml
  tkinter   # 可选，用于 GUI 审批弹窗
  ```

### 2. 安装与运行
```bash
git clone <your-repo-url>
cd CVA

# 创建虚拟环境（推荐）
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

pip install -r requirements.txt

# 启动默认开发者角色
python -m core.shell --manifest roles/developer-v1.yaml
```

启动后直接在终端输入任务，Agent 将自动规划、申请权限并执行工具。

### 3. 使用自定义角色
```bash
python cv_agent.py --manifest roles/code-reviewer-sample-v1.yaml --model deepseek/deepseek-chat
```

---

## 📋 角色配置（Manifest YAML）

每个角色通过一个独立的 YAML 文件定义，主要包含：
- `identity_prompt`（系统提示词）
- `init_permissions`（初始权限白名单）
- `capabilities`（可用工具列表）
- `escalation_policy`（审批策略）

**示例**（developer-v1.yaml 关键片段）：
```yaml
role_name: cva-developer-v1
init_permissions:
  read:
    - "core/**"
    - "*.py"
    - "!agent_workspace/**"
  write:
    - "agent_workspace/**"
capabilities:
  - execute_python_script
  - submit_plan
escalation_policy:
  auto_deny_patterns:
    - "/etc/**"
    - "**/.env"
```

---

## 🔐 安全特性详解

- **路径穿越防护**：`_secure_normalize` + 符号链接安全解析 + 危险前缀阻断
- **Shell 注入防护**：`shlex.split` + `shell=False`
- **内容大小限制**：写入 ≤50MB，读取 ≤30,000 字符
- **自省拦截**：高危工具执行前二次审查
- **审计全覆盖**：权限变更、工具调用、审批决策全部记录
- **测试覆盖**：`test_security_fixes.py` 与 `test_code_verification.py` 全部通过

---

## 📊 性能优化亮点

- Token 预算默认降低至 **50,000**
- 脱水缓存 TTL 延长至 **60 秒**
- 权限匹配采用 LRU 缓存
- 危险命令检测使用集合 O(1) 查找
- 内存截断策略优先丢弃 `NOISE` 消息

---

## 🧪 测试套件

项目内置完整测试套件，可直接运行验证：

```bash
# 安全修复验证
python tests/test_security_fixes.py

# 性能测试
python tests/test_performance.py

# Token 优化验证
python tests/test_token_optimization.py

# 全工具集成测试
python tests/test_universal_shell_capabilities.py
```

所有测试均 100% 通过。

---

## 📖 使用场景推荐

- **开发者**：`developer-v1.yaml` —— 代码生成、调试、重构
- **代码审查员**：`code-reviewer-sample-v1.yaml` —— 安全审计
- **DBA**：`dba-assistant-sample-v1.yaml` —— SQL 优化与日志分析
- **SRE**：`sre-log-analyst-sample-v1.yaml` —— 故障定位与告警处理

---

## 📄 License

本项目采用 **Apache License 2.0** 开源协议。  
欢迎 Fork、贡献与商业使用（请严格遵守安全规范）。

---

**Made with ❤️ for safe & powerful AI agents**

**CVA** —— 让大模型真正成为可信的生产力工具。