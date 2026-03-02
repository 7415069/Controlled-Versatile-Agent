"""
LiteLLM 适配层（LLM Adapter）v2
新增：structured_chat() — 用 function calling 强制结构化输出，零正则解析。

支持的模型示例（litellm 格式）：
  claude-opus-4-5              → Anthropic
  gpt-4o                       → OpenAI
  gemini/gemini-2.0-flash      → Google
  ollama/qwen2.5:14b           → 本地 Ollama
  deepseek/deepseek-chat        → DeepSeek
  groq/llama3-70b-8192          → Groq
"""

import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, TypeVar

import litellm
from litellm import completion

litellm.set_verbose = False

T = TypeVar("T")


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


# ─── 适配器主类 ───────────────────────────────────────────────

class LLMAdapter:
  """
  基于 litellm 的统一 LLM 适配器。
  - chat()            : 普通多轮对话（支持工具调用）
  - structured_chat() : 强制结构化输出，用 function_call 代替 JSON 提示词
  """

  def __init__(self, model: str, **kwargs):
    self._model = model
    self._extra_kwargs = kwargs

  @property
  def model(self) -> str:
    return self._model

  # ── 普通对话 ──────────────────────────────────────────────

  def chat(
      self,
      messages: List[Dict],
      system_prompt: str,
      tools: Optional[List[Dict]] = None,
      max_tokens: int = 8192,
      temperature: float = 0.0,
  ) -> LLMResponse:
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
      return LLMResponse(text=f"[LLM 调用失败] {e}", tool_calls=[], finish_reason="error")

    return self._parse_response(response)

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

    原理：把"期望的输出结构"包装成一个只有一个工具的工具集，
         并设置 tool_choice={"type":"function","function":{"name":...}}
         强制 LLM 必须调用该工具，从而保证输出符合 JSON Schema。

    返回：解析后的 dict，失败时返回 None（调用方按保守策略处理）。
    """
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
      "max_tokens": max_tokens,
      "temperature": temperature,
      "tools": forced_tool,
      # 强制必须调用这个工具，不允许纯文本回复
      "tool_choice": {
        "type": "function",
        "function": {"name": function_name},
      },
      **self._extra_kwargs,
    }

    try:
      response = completion(**kwargs)
    except Exception as e:
      print(f"[LLMAdapter] structured_chat 调用失败: {e}")
      return None

    # 提取工具调用参数
    try:
      choice = response.choices[0]
      message = choice.message
      if not (hasattr(message, "tool_calls") and message.tool_calls):
        print("[LLMAdapter] structured_chat: 未返回 tool_call，降级失败")
        return None

      tc = message.tool_calls[0]
      arguments = tc.function.arguments
      if isinstance(arguments, str):
        return json.loads(arguments)
      elif isinstance(arguments, dict):
        return arguments
      else:
        print(f"[LLMAdapter] structured_chat: 未知 arguments 类型 {type(arguments)}")
        return None

    except (json.JSONDecodeError, IndexError, AttributeError) as e:
      print(f"[LLMAdapter] structured_chat 解析失败: {e}")
      return None

  # ── 内部解析 ──────────────────────────────────────────────

  def _parse_response(self, response) -> LLMResponse:
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
  return {"role": "tool", "tool_call_id": tool_use_id, "content": content}


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
