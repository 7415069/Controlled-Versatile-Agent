"""
LiteLLM 适配层（LLM Adapter）
将 litellm 的通用接口统一封装为 CVA 内部使用的标准格式，
屏蔽不同模型提供商之间的 API 差异。

支持的模型示例（litellm 格式）：
  claude-opus-4-5              → Anthropic（默认，无需前缀）
  gpt-4o                       → OpenAI
  gemini/gemini-2.0-flash      → Google
  ollama/qwen2.5:14b           → 本地 Ollama
  deepseek/deepseek-chat        → DeepSeek
  groq/llama3-70b-8192          → Groq
"""

import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import litellm
from litellm import completion

# 关闭 litellm 的冗余日志
litellm.set_verbose = False


# ─── 统一响应数据结构 ─────────────────────────────────────────

@dataclass
class ToolCall:
  id: str
  name: str
  input: Dict


@dataclass
class LLMResponse:
  """CVA 内部统一的 LLM 响应结构，屏蔽底层差异"""
  text: str  # 文本内容（可为空）
  tool_calls: List[ToolCall]  # 工具调用列表（可为空）
  finish_reason: str  # "stop" | "tool_calls" | "length" | "error"
  usage: Dict = field(default_factory=dict)  # token 用量


# ─── 适配器主类 ───────────────────────────────────────────────

class LLMAdapter:
  """
  基于 litellm 的统一 LLM 适配器。
  对外只暴露一个 chat() 方法，返回 LLMResponse。
  """

  def __init__(self, model: str, **kwargs):
    """
    model: litellm 格式的模型名，例如：
      "claude-opus-4-5"
      "gpt-4o"
      "ollama/qwen2.5:14b"
      "gemini/gemini-2.0-flash"
    """
    self._model = model
    self._extra_kwargs = kwargs  # 传递给 litellm.completion 的额外参数

  @property
  def model(self) -> str:
    return self._model

  def chat(
      self,
      messages: List[Dict],
      system_prompt: str,
      tools: Optional[List[Dict]] = None,
      max_tokens: int = 8192,
      temperature: float = 0.0,
  ) -> LLMResponse:
    """
    发起一次 LLM 对话，返回统一格式的 LLMResponse。

    注意：system_prompt 以 litellm 标准方式注入（{"role":"system","content":...}）
    而非 Anthropic 专有的 system 参数，确保跨模型兼容。
    """
    # 构造完整消息列表（system 作为首条消息）
    full_messages = [{"role": "system", "content": system_prompt}] + messages

    kwargs: Dict[str, Any] = {
      "model": self._model,
      "messages": full_messages,
      "max_tokens": max_tokens,
      "temperature": temperature,
      **self._extra_kwargs,
    }

    if tools:
      kwargs["tools"] = _convert_tools_to_litellm(tools)
      kwargs["tool_choice"] = "auto"

    try:
      response = completion(**kwargs)
    except Exception as e:
      return LLMResponse(
          text=f"[LLM 调用失败] {e}",
          tool_calls=[],
          finish_reason="error",
      )

    return self._parse_response(response)

  # ─── 解析响应 ─────────────────────────────────────────────

  def _parse_response(self, response) -> LLMResponse:
    choice = response.choices[0]
    message = choice.message
    finish_reason = choice.finish_reason or "stop"

    text = message.content or ""
    tool_calls: List[ToolCall] = []

    # 解析工具调用（litellm 统一格式）
    if hasattr(message, "tool_calls") and message.tool_calls:
      finish_reason = "tool_calls"
      for tc in message.tool_calls:
        try:
          arguments = tc.function.arguments
          if isinstance(arguments, str):
            parsed_input = json.loads(arguments)
          else:
            parsed_input = arguments or {}
        except (json.JSONDecodeError, Exception):
          parsed_input = {}

        tool_calls.append(ToolCall(
            id=tc.id,
            name=tc.function.name,
            input=parsed_input,
        ))

    # token 用量
    usage = {}
    if hasattr(response, "usage") and response.usage:
      usage = {
        "prompt_tokens": getattr(response.usage, "prompt_tokens", 0),
        "completion_tokens": getattr(response.usage, "completion_tokens", 0),
        "total_tokens": getattr(response.usage, "total_tokens", 0),
      }

    return LLMResponse(
        text=text,
        tool_calls=tool_calls,
        finish_reason=finish_reason,
        usage=usage,
    )


# ─── 工具格式转换 ─────────────────────────────────────────────

def _convert_tools_to_litellm(tools: List[Dict]) -> List[Dict]:
  """
  将 CVA 内部工具格式转换为 litellm/OpenAI 标准 function calling 格式。

  CVA 内部格式（Anthropic 风格）:
      {"name": "...", "description": "...", "input_schema": {...}}

  litellm/OpenAI 格式:
      {"type": "function", "function": {"name": "...", "description": "...", "parameters": {...}}}
  """
  converted = []
  for tool in tools:
    converted.append({
      "type": "function",
      "function": {
        "name": tool["name"],
        "description": tool.get("description", ""),
        "parameters": tool.get("input_schema", {"type": "object", "properties": {}}),
      }
    })
  return converted


def convert_tool_result_to_litellm(tool_use_id: str, content: str) -> Dict:
  """
  将工具执行结果转换为 litellm/OpenAI 标准格式。

  litellm 格式：
      {"role": "tool", "tool_call_id": "...", "content": "..."}
  """
  return {
    "role": "tool",
    "tool_call_id": tool_use_id,
    "content": content,
  }


def convert_assistant_with_tools_to_litellm(
    text: str, tool_calls: List[ToolCall]
) -> Dict:
  """
  将 LLM 助手消息（含工具调用）转换为 litellm/OpenAI 标准格式，
  用于追加到对话历史中。
  """
  msg: Dict[str, Any] = {"role": "assistant"}
  if text:
    msg["content"] = text
  else:
    msg["content"] = None

  if tool_calls:
    msg["tool_calls"] = [
      {
        "id": tc.id,
        "type": "function",
        "function": {
          "name": tc.name,
          "arguments": json.dumps(tc.input, ensure_ascii=False),
        },
      }
      for tc in tool_calls
    ]

  return msg
