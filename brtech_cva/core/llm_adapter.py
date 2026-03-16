"""
LiteLLM 适配层（LLM Adapter）v3.3
修复 P1-3：__init__ 中 _extra_kwargs 与 kwargs 指向同一 dict，
           pop 操作同时修改了 _extra_kwargs，导致透传参数全部丢失。
           修复方法：先 pop 所有已知 key，再把剩余的 kwargs 赋给 _extra_kwargs。
"""

import json
import logging
import re
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, TypeVar, cast, Any

import litellm
from litellm import completion

from brtech_cva.core.config import cva_settings
from brtech_cva.core.logger import trace_logger

logger = logging.getLogger(__name__)
litellm.set_verbose = False
T = TypeVar("T")


class LLMErrorType(Enum):
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
  error_type: LLMErrorType
  message: str
  retry_after: Optional[float] = None
  status_code: Optional[int] = None


@dataclass
class ToolCall:
  id: str
  name: str
  input: Dict


@dataclass
class LLMResponse:
  text: str
  tool_calls: List[ToolCall]
  finish_reason: str
  usage: Dict = field(default_factory=dict)
  error: Optional[LLMError] = None
  response_time: float = 0.0


@dataclass
class CallStats:
  total_calls: int = 0
  successful_calls: int = 0
  failed_calls: int = 0
  total_tokens: int = 0
  total_response_time: float = 0.0
  error_counts: Dict[LLMErrorType, int] = field(default_factory=dict)


class LLMAdapter:
  def __init__(self, model: str, **kwargs):
    self._model = model

    # 修复 P1-3：先 pop 所有已知参数，再把剩余的 kwargs 赋给 _extra_kwargs。
    # 原来的代码先做 `self._extra_kwargs = kwargs`（两个变量指向同一 dict），
    # 再调用 kwargs.pop()，导致 _extra_kwargs 也被修改，最终变成空 dict。
    self._max_retries = kwargs.pop('max_retries', cva_settings.llm_settings.max_retries)
    self._retry_delay = kwargs.pop('retry_delay', cva_settings.llm_settings.retry_delay)
    self._timeout = kwargs.pop('timeout', cva_settings.llm_settings.timeout)
    self._max_input_length = kwargs.pop('max_input_length', cva_settings.llm_settings.max_input_length)
    self._max_output_tokens = kwargs.pop('max_output_tokens', cva_settings.llm_settings.max_output_tokens)

    # pop 完已知 key 后，剩余的才是真正需要透传给 litellm 的参数
    self._extra_kwargs = dict(kwargs)

    self._lock = threading.RLock()
    self._stats = CallStats()

  @property
  def model(self) -> str:
    return self._model

  @property
  def stats(self) -> CallStats:
    with self._lock:
      return CallStats(
          total_calls=self._stats.total_calls,
          successful_calls=self._stats.successful_calls,
          failed_calls=self._stats.failed_calls,
          total_tokens=self._stats.total_tokens,
          total_response_time=self._stats.total_response_time,
          error_counts=dict(self._stats.error_counts),
      )

  def chat(self, messages: List[Dict], system_prompt: str, tools: Optional[List[Dict]] = None,
      max_tokens: int = 8192, temperature: float = 0.0) -> LLMResponse:
    start_time = time.time()
    validation_error = self._validate_chat_request(messages, system_prompt, tools, max_tokens)
    if validation_error:
      return LLMResponse(
          text=f"[请求验证失败] {validation_error}",
          tool_calls=[],
          finish_reason="error",
          error=LLMError(LLMErrorType.INVALID_REQUEST, validation_error),
          response_time=time.time() - start_time
      )

    full_payload = [{"role": "system", "content": system_prompt}] + messages
    trace_logger.debug(f"--- [LLM REQUEST] ---")
    trace_logger.debug(f"Model: {self._model}")
    trace_logger.debug(f"Full Payload:\n{full_payload}")
    trace_logger.debug(f"Message History Count: {len(messages)}")

    response, error = self._call_with_retry(self._do_chat_call, messages, system_prompt, tools, max_tokens, temperature)
    response_time = time.time() - start_time
    self._update_stats(response, error, response_time)
    if response:
      trace_logger.debug(f"--- [LLM RESPONSE] ---")
      trace_logger.debug(f"Finish Reason: {response.finish_reason}")
      trace_logger.debug(f"Text Content: {response.text[:500]}...")
      response.response_time = response_time
    return response or LLMResponse(
        text=f"[LLM 调用失败] {error.message if error else '未知错误'}",
        tool_calls=[],
        finish_reason="error",
        error=error,
        response_time=response_time
    )

  def structured_chat(self, messages: List[Dict], system_prompt: str, output_schema: Dict,
      function_name: str, function_description: str,
      max_tokens: int = 1024, temperature: float = 0.0) -> Optional[Dict]:
    validation_error = self._validate_structured_request(messages, system_prompt, output_schema, function_name, max_tokens)
    if validation_error:
      return None
    response, error = self._call_with_retry(
        self._do_structured_call,
        messages, system_prompt, output_schema, function_name, function_description, max_tokens, temperature
    )
    return response

  def _call_with_retry(self, call_func, *args):
    last_error = None
    for attempt in range(self._max_retries + 1):
      try:
        if attempt > 0:
          time.sleep(min(self._retry_delay * (2 ** (attempt - 1)), 30))
        result = call_func(*args)
        if result is not None:
          return result, None
      except Exception as e:
        last_error = self._classify_error(e)
        if last_error.error_type in [LLMErrorType.AUTH_ERROR, LLMErrorType.INVALID_REQUEST]:
          break
    return None, last_error

  def _do_chat_call(self, messages, system_prompt, tools, max_tokens, temperature):
    processed_messages = []
    for msg in messages:
      # 截图在 tool 消息里，但绝大多数模型（包括 GLM-4V）不接受 role=tool 里带图片。
      # 处理策略：
      #   1. tool 消息保留，但把 base64 替换成占位文本（保持 tool_call_id 配对完整）
      #   2. 如果 base64 未被脱水（即是最新截图），紧跟其后插入一条 role=user 的图片消息
      if msg["role"] == "tool" and '"artifact_type": "image"' in str(msg["content"]):
        try:
          data = json.loads(msg["content"])
          b64 = data["data"].get("base64", "")
          is_dehydrated = data["data"].get("is_dehydrated", False) or b64 == "[DEHYDRATED]"

          # tool 消息：把 base64 替换为占位符，避免把巨大 base64 塞进 tool role
          data["data"]["base64"] = "[图片已单独发送]"
          processed_messages.append({
            "role": "tool",
            "tool_call_id": msg["tool_call_id"],
            "content": json.dumps(data, ensure_ascii=False)
          })

          # 只有未脱水的最新截图才需要真正发图
          if not is_dehydrated and b64 and b64 != "[DEHYDRATED]":
            processed_messages.append({
              "role": "user",
              "content": [
                {"type": "text", "text": "[截图] 以上工具操作后的屏幕状态："},
                {"type": "image_url", "image_url": {"url": f"data:image/jpeg;base64,{b64}"}}
              ]
            })
          continue
        except Exception:
          pass
      processed_messages.append(msg)
    full_messages = [{"role": "system", "content": system_prompt}] + processed_messages
    kwargs = {
      "model": self._model,
      "messages": full_messages,
      "max_tokens": min(max_tokens, self._max_output_tokens),
      "temperature": temperature,
      "timeout": self._timeout,
      **self._extra_kwargs  # 现在能正确透传调用方传入的额外参数
    }
    if tools:
      kwargs["tools"] = _convert_tools_to_litellm(tools)
      kwargs["tool_choice"] = "auto"
    res = completion(**kwargs)
    return self._parse_response(cast(Any, res))

  def _do_structured_call(self, messages, system_prompt, output_schema, function_name, function_description, max_tokens, temperature):
    forced_tool = [{"type": "function", "function": {"name": function_name, "description": function_description, "parameters": output_schema}}]
    full_messages = [{"role": "system", "content": system_prompt}] + messages
    kwargs = {
      "model": self._model,
      "messages": full_messages,
      "max_tokens": min(max_tokens, self._max_output_tokens),
      "temperature": temperature,
      "timeout": self._timeout,
      "tools": forced_tool,
      "tool_choice": {"type": "function", "function": {"name": function_name}},
      **self._extra_kwargs
    }
    return self._parse_structured_response(completion(**kwargs))

  def _validate_chat_request(self, messages, system_prompt, tools, max_tokens):
    if not messages:
      return "messages 不能为空"
    total_length = len(system_prompt)
    for msg in messages:
      content = msg.get("content", "")
      if isinstance(content, list):  # 处理多模态列表 [NEW]
        for item in content:
          if item.get("type") == "text":
            total_length += len(item.get("text", ""))
          elif item.get("type") == "image_url":
            total_length += 1000  # 图片按 1000 字符估算，不要按 Base64 长度算
      else:
        total_length += len(str(content))

    if total_length > self._max_input_length:
      return f"总长度超过限制: {total_length} > {self._max_input_length}"
    return None

  def _validate_structured_request(self, messages, system_prompt, output_schema, function_name, max_tokens):
    return self._validate_chat_request(messages, system_prompt, None, max_tokens)

  def _classify_error(self, exception):
    msg = str(exception).lower()
    if 'auth' in msg or 'api key' in msg:
      return LLMError(LLMErrorType.AUTH_ERROR, str(exception))
    if 'rate limit' in msg:
      return LLMError(LLMErrorType.RATE_LIMIT, str(exception))
    if 'timeout' in msg:
      return LLMError(LLMErrorType.TIMEOUT, str(exception))
    # 图片格式错误：重试没意义，直接标为 INVALID_REQUEST 跳出重试循环
    if '图片' in msg or 'image' in msg or 'vision' in msg:
      return LLMError(LLMErrorType.INVALID_REQUEST, str(exception))
    return LLMError(LLMErrorType.UNKNOWN_ERROR, str(exception))

  def _parse_response(self, response):
    msg = response.choices[0].message
    text = msg.content or ""
    tool_calls = []
    if hasattr(msg, "tool_calls") and msg.tool_calls:
      for tc in msg.tool_calls:
        try:
          raw_args = tc.function.arguments
          if isinstance(raw_args, str):
            cleaned_args_str = self._clean_hallucinated_xml(raw_args)
            args = json.loads(cleaned_args_str)
          else:
            args = raw_args

          args = self._clean_dict_values(args)
          tool_calls.append(ToolCall(id=tc.id, name=tc.function.name, input=args))
        except Exception as e:
          logger.error(f"解析工具参数失败: {e}, 原始数据: {tc.function.arguments}")
          pass
    usage = {"total_tokens": getattr(response.usage, "total_tokens", 0)}
    return LLMResponse(
        text=text,
        tool_calls=tool_calls,
        finish_reason=response.choices[0].finish_reason or "stop",
        usage=usage
    )

  def _parse_structured_response(self, response):
    try:
      args = response.choices[0].message.tool_calls[0].function.arguments
      if isinstance(args, str):
        args = self._clean_hallucinated_xml(args)
        args = json.loads(args)
      return self._clean_dict_values(args)
    except Exception as e:
      logger.error(f"解析结构化响应失败: {e}")
      return None

  def _update_stats(self, resp, err, rtime):
    with self._lock:
      self._stats.total_calls += 1
      if resp and not err:
        self._stats.successful_calls += 1
        if resp.usage:
          self._stats.total_tokens += resp.usage.get("total_tokens", 0)
        self._stats.total_response_time += rtime
      else:
        self._stats.failed_calls += 1
        if err:
          self._stats.error_counts[err.error_type] = self._stats.error_counts.get(err.error_type, 0) + 1

  def _clean_hallucinated_xml(self, text: str) -> str:
    """
    专门针对 GLM 等模型产生的 <arg_key> 这种 XML 幻觉进行清洗
    """
    if not text:
      return ""

    # 1. 移除 <arg_key>key</arg_key> 这种标签，只保留中间的内容
    # 匹配 <arg_key>内容</arg_key> 并替换为 内容
    text = re.sub(r'<arg_key>(.*?)</arg_key>', r'\1', text)
    text = re.sub(r'<arg_value>(.*?)</arg_value>', r'\1', text)

    # 2. 移除残留的孤立标签
    text = re.sub(r'</?arg_.*?>', '', text)

    # 3. 修复模型可能在 JSON 字段名里塞进换行符的问题
    # 比如 "action": "key\n" -> "action": "key"
    return text.strip()

  def _clean_dict_values(self, d):
    if isinstance(d, dict):
      return {k: self._clean_dict_values(v) for k, v in d.items()}
    elif isinstance(d, list):
      return [self._clean_dict_values(v) for v in d]
    elif isinstance(d, str):
      return self._clean_hallucinated_xml(d)
    return d


def _convert_tools_to_litellm(tools):
  return [{"type": "function", "function": {"name": t["name"], "description": t.get("description", ""), "parameters": t.get("input_schema", {})}} for t in tools]


def convert_tool_result_to_litellm(tool_use_id: str, content: str) -> dict:
  return {
    "role": "tool",
    "tool_call_id": tool_use_id,
    "content": content if content else "{}"
  }


def convert_assistant_with_tools_to_litellm(text: str, tool_calls: List[ToolCall]) -> dict:
  msg: Dict[str, Any] = {"role": "assistant", "content": text if text else ""}
  if tool_calls:
    msg["tool_calls"] = [
      {
        "id": tc.id,
        "type": "function",
        "function": {
          "name": tc.name,
          "arguments": json.dumps(tc.input, ensure_ascii=False)
        }
      } for tc in tool_calls
    ]
  return msg
