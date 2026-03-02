"""
LiteLLM 适配层（LLM Adapter）v3 - 错误处理增强版
新增：structured_chat() — 用 function calling 强制结构化输出，零正则解析。

支持的模型示例（litellm 格式）：
  claude-opus-4-5              → Anthropic
  gpt-4o                       → OpenAI
  gemini/gemini-2.0-flash      → Google
  ollama/qwen2.5:14b           → 本地 Ollama
  deepseek/deepseek-chat        → DeepSeek
  groq/llama3-70b-8192          → Groq

安全改进：
- 增强错误处理：添加重试机制和详细错误分类
- 改进超时管理：防止长时间阻塞
- 添加请求验证：防止恶意输入
- 增强响应验证：确保数据完整性
- 性能监控：记录调用耗时和成功率
"""

import json
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, TypeVar

import litellm
from litellm import completion

litellm.set_verbose = False

T = TypeVar("T")


# ─── 错误类型定义 ─────────────────────────────────────────────

class LLMErrorType(Enum):
  """LLM调用错误类型"""
  NETWORK_ERROR = "network_error"
  RATE_LIMIT = "rate_limit"
  AUTH_ERROR = "auth_error"
  MODEL_ERROR = "model_error"
  TIMEOUT = "timeout"
  INVALID_REQUEST = "invalid_request"
  CONTENT_FILTER = "content_filter"
  SERVER_ERROR = "server_error"
  UNKNOWN_ERROR = "unknown_error"


@dataclass
class LLMError:
  """LLM调用错误详情"""
  error_type: LLMErrorType
  message: str
  retry_after: Optional[float] = None
  status_code: Optional[int] = None


# ─── 统一响应数据结构 ─────────────────────────────────────────

@dataclass
class ToolCall:
  id: str
  name: str
  input: Dict


@dataclass
class LLMResponse:
  """普通对话响应"""
  text: str
  tool_calls: List[ToolCall]
  finish_reason: str  # "stop" | "tool_calls" | "length" | "error"
  usage: Dict = field(default_factory=dict)
  error: Optional[LLMError] = None
  response_time: float = 0.0


@dataclass
class CallStats:
  """调用统计信息"""
  total_calls: int = 0
  successful_calls: int = 0
  failed_calls: int = 0
  total_tokens: int = 0
  total_response_time: float = 0.0
  error_counts: Dict[LLMErrorType, int] = field(default_factory=dict)


# ─── 适配器主类 ───────────────────────────────────────────────

class LLMAdapter:
  """
  基于 litellm 的统一 LLM 适配器。
  - chat()            : 普通多轮对话（支持工具调用）
  - structured_chat() : 强制结构化输出，用 function_call 代替 JSON 提示词
  
  安全增强：
  - 智能重试机制
  - 详细的错误分类和处理
  - 请求验证和响应验证
  - 性能监控和统计
  """

  def __init__(self, model: str, **kwargs):
    self._model = model
    self._extra_kwargs = kwargs

    # 重试配置
    self._max_retries = kwargs.pop('max_retries', 3)
    self._retry_delay = kwargs.pop('retry_delay', 1.0)
    self._timeout = kwargs.pop('timeout', 60)

    # 线程安全
    self._lock = threading.RLock()

    # 统计信息
    self._stats = CallStats()

    # 请求限制
    self._max_input_length = kwargs.pop('max_input_length', 100000)
    self._max_output_tokens = kwargs.pop('max_output_tokens', 8192)

  @property
  def model(self) -> str:
    return self._model

  @property
  def stats(self) -> CallStats:
    """获取调用统计信息"""
    with self._lock:
      return CallStats(
          total_calls=self._stats.total_calls,
          successful_calls=self._stats.successful_calls,
          failed_calls=self._stats.failed_calls,
          total_tokens=self._stats.total_tokens,
          total_response_time=self._stats.total_response_time,
          error_counts=dict(self._stats.error_counts)
      )

  # ── 普通对话 ──────────────────────────────────────────────

  def chat(
      self,
      messages: List[Dict],
      system_prompt: str,
      tools: Optional[List[Dict]] = None,
      max_tokens: int = 8192,
      temperature: float = 0.0,
  ) -> LLMResponse:
    """普通多轮对话，支持工具调用和重试机制"""
    start_time = time.time()

    # 请求验证
    validation_error = self._validate_chat_request(messages, system_prompt, tools, max_tokens)
    if validation_error:
      return LLMResponse(
          text=f"[请求验证失败] {validation_error}",
          tool_calls=[],
          finish_reason="error",
          error=LLMError(LLMErrorType.INVALID_REQUEST, validation_error),
          response_time=time.time() - start_time
      )

    # 执行调用（带重试）
    response, error = self._call_with_retry(
        self._do_chat_call,
        messages, system_prompt, tools, max_tokens, temperature
    )

    # 更新统计
    response_time = time.time() - start_time
    self._update_stats(response, error, response_time)

    if response:
      response.response_time = response_time
    return response or LLMResponse(
        text=f"[LLM 调用失败] {error.message if error else '未知错误'}",
        tool_calls=[],
        finish_reason="error",
        error=error,
        response_time=response_time
    )

  # ── 结构化输出（核心新增）─────────────────────────────────

  def structured_chat(
      self,
      messages: List[Dict],
      system_prompt: str,
      output_schema: Dict,  # JSON Schema，描述期望的输出结构
      function_name: str,  # 工具名，语义清晰即可
      function_description: str,  # 工具描述，帮助模型理解填什么
      max_tokens: int = 1024,
      temperature: float = 0.0,
  ) -> Optional[Dict]:
    """
    通过 function calling 强制 LLM 输出结构化数据。
    
    安全增强：
    - 请求验证
    - 重试机制
    - 响应验证
    - 详细错误处理
    """
    start_time = time.time()

    # 请求验证
    validation_error = self._validate_structured_request(
        messages, system_prompt, output_schema, function_name, max_tokens
    )
    if validation_error:
      print(f"[LLMAdapter] structured_chat 请求验证失败: {validation_error}")
      return None

    # 执行调用（带重试）
    response, error = self._call_with_retry(
        self._do_structured_call,
        messages, system_prompt, output_schema, function_name, function_description,
        max_tokens, temperature
    )

    # 更新统计
    response_time = time.time() - start_time
    self._update_stats(None, error, response_time)

    if response is None and error:
      print(f"[LLMAdapter] structured_chat 最终失败: {error.message}")

    return response

  # ── 内部调用方法 ────────────────────────────────────────────

  def _call_with_retry(self, call_func, *args) -> tuple[Optional[Any], Optional[LLMError]]:
    """带重试机制的调用包装器"""
    last_error = None

    for attempt in range(self._max_retries + 1):
      try:
        if attempt > 0:
          # 指数退避
          delay = self._retry_delay * (2 ** (attempt - 1))
          if last_error and last_error.retry_after:
            delay = max(delay, last_error.retry_after)
          time.sleep(min(delay, 30))  # 最大等待30秒

        result = call_func(*args)
        if result is not None:
          return result, None

      except Exception as e:
        last_error = self._classify_error(e)
        print(f"[LLMAdapter] 第{attempt + 1}次调用失败: {last_error.message}")

        # 某些错误不适合重试
        if last_error.error_type in [LLMErrorType.AUTH_ERROR, LLMErrorType.INVALID_REQUEST]:
          break

    return None, last_error

  def _do_chat_call(self, messages, system_prompt, tools, max_tokens, temperature):
    """执行实际的chat调用"""
    full_messages = [{"role": "system", "content": system_prompt}] + messages

    kwargs: Dict[str, Any] = {
      "model": self._model,
      "messages": full_messages,
      "max_tokens": min(max_tokens, self._max_output_tokens),
      "temperature": temperature,
      "timeout": self._timeout,
      **self._extra_kwargs,
    }

    if tools:
      kwargs["tools"] = _convert_tools_to_litellm(tools)
      kwargs["tool_choice"] = "auto"

    response = completion(**kwargs)
    return self._parse_response(response)

  def _do_structured_call(self, messages, system_prompt, output_schema,
      function_name, function_description, max_tokens, temperature):
    """执行实际的structured_chat调用"""
    # 将输出 schema 包装为单个强制工具
    forced_tool = [{
      "type": "function",
      "function": {
        "name": function_name,
        "description": function_description,
        "parameters": output_schema,
      }
    }]

    full_messages = [{"role": "system", "content": system_prompt}] + messages

    kwargs: Dict[str, Any] = {
      "model": self._model,
      "messages": full_messages,
      "max_tokens": min(max_tokens, self._max_output_tokens),
      "temperature": temperature,
      "timeout": self._timeout,
      "tools": forced_tool,
      # 强制必须调用这个工具，不允许纯文本回复
      "tool_choice": {
        "type": "function",
        "function": {"name": function_name},
      },
      **self._extra_kwargs,
    }

    response = completion(**kwargs)
    return self._parse_structured_response(response)

  # ── 验证方法 ───────────────────────────────────────────────

  def _validate_chat_request(self, messages, system_prompt, tools, max_tokens) -> Optional[str]:
    """验证chat请求参数"""
    if not isinstance(messages, list) or not messages:
      return "messages 必须是非空列表"

    if not isinstance(system_prompt, str) or len(system_prompt) > 10000:
      return "system_prompt 必须是字符串且长度不超过10000字符"

    if max_tokens <= 0 or max_tokens > self._max_output_tokens:
      return f"max_tokens 必须在1-{self._max_output_tokens}之间"

    # 检查消息格式
    total_length = len(system_prompt)
    for msg in messages:
      if not isinstance(msg, dict):
        return "messages 中的每个元素必须是字典"

      if "role" not in msg or "content" not in msg:
        return "messages 中的每个字典必须包含 role 和 content 字段"

      if msg["role"] not in ["user", "assistant", "system"]:
        return "role 必须是 user、assistant 或 system"

      content = msg["content"]
      if isinstance(content, str):
        total_length += len(content)
      elif isinstance(content, list):
        total_length += sum(len(str(item)) for item in content)

      if total_length > self._max_input_length:
        return f"输入总长度超过限制: {total_length} > {self._max_input_length}"

    return None

  def _validate_structured_request(self, messages, system_prompt, output_schema,
      function_name, max_tokens) -> Optional[str]:
    """验证structured_chat请求参数"""
    base_error = self._validate_chat_request(messages, system_prompt, None, max_tokens)
    if base_error:
      return base_error

    if not isinstance(output_schema, dict) or not output_schema:
      return "output_schema 必须是非空字典"

    if not isinstance(function_name, str) or not function_name:
      return "function_name 必须是非空字符串"

    # 简单的schema验证
    if "type" not in output_schema or output_schema["type"] != "object":
      return "output_schema 必须是 object 类型"

    return None

  # ── 错误分类 ───────────────────────────────────────────────

  def _classify_error(self, exception: Exception) -> LLMError:
    """分类异常为LLMError"""
    error_msg = str(exception)

    # 网络错误
    if any(keyword in error_msg.lower() for keyword in ['connection', 'network', 'dns']):
      return LLMError(LLMErrorType.NETWORK_ERROR, error_msg)

    # 认证错误
    if any(keyword in error_msg.lower() for keyword in ['auth', 'unauthorized', 'api key']):
      return LLMError(LLMErrorType.AUTH_ERROR, error_msg)

    # 速率限制
    if any(keyword in error_msg.lower() for keyword in ['rate limit', 'quota', 'too many requests']):
      retry_after = 60.0  # 默认60秒
      try:
        import re
        match = re.search(r'retry after (\d+)', error_msg.lower())
        if match:
          retry_after = float(match.group(1))
      except:
        pass
      return LLMError(LLMErrorType.RATE_LIMIT, error_msg, retry_after)

    # 超时
    if any(keyword in error_msg.lower() for keyword in ['timeout', 'timed out']):
      return LLMError(LLMErrorType.TIMEOUT, error_msg)

    # 模型错误
    if any(keyword in error_msg.lower() for keyword in ['model', 'not found', 'invalid model']):
      return LLMError(LLMErrorType.MODEL_ERROR, error_msg)

    # 内容过滤
    if any(keyword in error_msg.lower() for keyword in ['content filter', 'safety', 'policy']):
      return LLMError(LLMErrorType.CONTENT_FILTER, error_msg)

    # 服务器错误
    if any(keyword in error_msg.lower() for keyword in ['server error', 'internal error', '502', '503']):
      return LLMError(LLMErrorType.SERVER_ERROR, error_msg)

    # 未知错误
    return LLMError(LLMErrorType.UNKNOWN_ERROR, error_msg)

  # ── 响应解析 ───────────────────────────────────────────────

  def _parse_response(self, response) -> LLMResponse:
    """解析普通chat响应"""
    try:
      choice = response.choices[0]
      message = choice.message
      finish_reason = choice.finish_reason or "stop"

      text = message.content or ""
      tool_calls: List[ToolCall] = []

      if hasattr(message, "tool_calls") and message.tool_calls:
        finish_reason = "tool_calls"
        for tc in message.tool_calls:
          try:
            arguments = tc.function.arguments
            parsed_input = json.loads(arguments) if isinstance(arguments, str) else (arguments or {})
          except (json.JSONDecodeError, Exception):
            parsed_input = {}
          tool_calls.append(ToolCall(id=tc.id, name=tc.function.name, input=parsed_input))

      usage = {}
      if hasattr(response, "usage") and response.usage:
        usage = {
          "prompt_tokens": getattr(response.usage, "prompt_tokens", 0),
          "completion_tokens": getattr(response.usage, "completion_tokens", 0),
          "total_tokens": getattr(response.usage, "total_tokens", 0),
        }

      return LLMResponse(text=text, tool_calls=tool_calls, finish_reason=finish_reason, usage=usage)

    except Exception as e:
      raise Exception(f"响应解析失败: {e}")

  def _parse_structured_response(self, response) -> Optional[Dict]:
    """解析结构化输出响应"""
    try:
      choice = response.choices[0]
      message = choice.message

      if not (hasattr(message, "tool_calls") and message.tool_calls):
        raise Exception("未返回 tool_call")

      tc = message.tool_calls[0]
      arguments = tc.function.arguments

      if isinstance(arguments, str):
        result = json.loads(arguments)
      elif isinstance(arguments, dict):
        result = arguments
      else:
        raise Exception(f"未知 arguments 类型 {type(arguments)}")

      # 验证结果是否符合schema（简单验证）
      if not isinstance(result, dict):
        raise Exception("结构化输出必须是字典")

      return result

    except (json.JSONDecodeError, IndexError, AttributeError, Exception) as e:
      raise Exception(f"结构化响应解析失败: {e}")

  # ── 统计更新 ───────────────────────────────────────────────

  def _update_stats(self, response: Optional[LLMResponse], error: Optional[LLMError], response_time: float):
    """更新调用统计信息"""
    with self._lock:
      self._stats.total_calls += 1
      self._stats.total_response_time += response_time

      if response and not error:
        self._stats.successful_calls += 1
        if response.usage:
          self._stats.total_tokens += response.usage.get("total_tokens", 0)
      else:
        self._stats.failed_calls += 1
        if error:
          self._stats.error_counts[error.error_type] = self._stats.error_counts.get(error.error_type, 0) + 1


# ─── 格式转换工具函数 ─────────────────────────────────────────

def _convert_tools_to_litellm(tools: list[dict]) -> list[dict]:
  """CVA 内部工具格式 → litellm/OpenAI function calling 格式"""
  return [
    {
      "type": "function",
      "function": {
        "name": t["name"],
        "description": t.get("description", ""),
        "parameters": t.get("input_schema", {"type": "object", "properties": {}}),
      }
    }
    for t in tools
  ]


def convert_tool_result_to_litellm(tool_use_id: str, content: str) -> dict:
  # return {"role": "tool", "tool_call_id": tool_use_id, "content": content}
  return {"role": "user", "tool_call_id": tool_use_id, "content": content}


def convert_assistant_with_tools_to_litellm(text: str, tool_calls: List[ToolCall]) -> dict:
  msg: dict[str, Any] = {"role": "assistant", "content": text if text else None}
  if tool_calls:
    msg["tool_calls"] = [
      {
        "id": tc.id,
        "type": "function",
        "function": {"name": tc.name, "arguments": json.dumps(tc.input, ensure_ascii=False)},
      }
      for tc in tool_calls
    ]
  return msg
