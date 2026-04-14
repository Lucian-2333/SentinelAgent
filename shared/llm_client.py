"""
shared/llm_client.py
─────────────────────────────────────────────────────────────────────────────
SentinelAgent — Unified LLM Client

统一封装所有 LLM 提供商的调用接口，支持：
  • DeepSeek      (OpenAI 兼容)
  • OpenAI        (原生)
  • Anthropic     (Claude 原生 SDK)
  • 任意 OpenAI 兼容端点  (Ollama / vLLM / 月之暗面 / 硅基流动 等)

通过 .env 中的 LLM_PROVIDER 环境变量切换，无需修改 agent 代码。
─────────────────────────────────────────────────────────────────────────────
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger("sentinel.llm_client")


@dataclass
class LLMResponse:
    """统一的 LLM 响应结构。"""
    text: str
    provider: str
    model: str


def _load_dotenv() -> None:
    """尝试加载 .env 文件（若安装了 python-dotenv）。"""
    try:
        from dotenv import load_dotenv
        load_dotenv()
    except ImportError:
        pass  # 没有 python-dotenv 时直接读已有环境变量


class LLMClient:
    """
    统一 LLM 调用客户端。

    用法示例：
        client = LLMClient()
        response = await client.chat(system_prompt, user_message)
        print(response.text)
    """

    def __init__(self) -> None:
        _load_dotenv()
        self.provider = os.getenv("LLM_PROVIDER", "deepseek").lower()
        self.max_tokens = int(os.getenv("LLM_MAX_TOKENS", "512"))
        self.temperature = float(os.getenv("LLM_TEMPERATURE", "0.1"))

    async def chat(self, system: str, user: str) -> LLMResponse:
        """
        发送 chat 请求，自动路由到配置的提供商。

        Args:
            system: 系统提示词
            user:   用户消息

        Returns:
            LLMResponse 包含 .text 原始字符串
        """
        logger.debug("LLMClient routing to provider=%s", self.provider)

        if self.provider == "anthropic":
            return await self._call_anthropic(system, user)
        else:
            # DeepSeek / OpenAI / openai_compatible 均走 OpenAI SDK 兼容路径
            return await self._call_openai_compatible(system, user)

    # ── OpenAI 兼容路径（DeepSeek / OpenAI / 自定义端点）────────────────────

    async def _call_openai_compatible(self, system: str, user: str) -> LLMResponse:
        try:
            from openai import AsyncOpenAI
        except ImportError:
            raise RuntimeError(
                "openai SDK 未安装。请运行: pip install openai"
            )

        api_key, base_url, model = self._resolve_openai_params()

        client = AsyncOpenAI(api_key=api_key, base_url=base_url)

        response = await client.chat.completions.create(
            model=model,
            max_tokens=self.max_tokens,
            temperature=self.temperature,
            messages=[
                {"role": "system", "content": system},
                {"role": "user",   "content": user},
            ],
        )

        text = response.choices[0].message.content or ""
        return LLMResponse(text=text, provider=self.provider, model=model)

    def _resolve_openai_params(self) -> tuple[str, str, str]:
        """根据 provider 返回 (api_key, base_url, model)。"""
        if self.provider == "deepseek":
            return (
                self._require_env("DEEPSEEK_API_KEY"),
                os.getenv("DEEPSEEK_BASE_URL", "https://api.deepseek.com"),
                os.getenv("DEEPSEEK_MODEL", "deepseek-chat"),
            )
        elif self.provider == "openai":
            return (
                self._require_env("OPENAI_API_KEY"),
                os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1"),
                os.getenv("OPENAI_MODEL", "gpt-4o"),
            )
        elif self.provider == "openai_compatible":
            return (
                self._require_env("OPENAI_COMPATIBLE_API_KEY"),
                self._require_env("OPENAI_COMPATIBLE_BASE_URL"),
                self._require_env("OPENAI_COMPATIBLE_MODEL"),
            )
        else:
            raise ValueError(
                f"未知的 LLM_PROVIDER='{self.provider}'。"
                "可选: deepseek | openai | anthropic | openai_compatible"
            )

    # ── Anthropic 原生路径 ────────────────────────────────────────────────────

    async def _call_anthropic(self, system: str, user: str) -> LLMResponse:
        try:
            import anthropic
        except ImportError:
            raise RuntimeError(
                "anthropic SDK 未安装。请运行: pip install anthropic"
            )

        api_key = self._require_env("ANTHROPIC_API_KEY")
        model   = os.getenv("ANTHROPIC_MODEL", "claude-opus-4-5")

        client = anthropic.AsyncAnthropic(api_key=api_key)
        response = await client.messages.create(
            model=model,
            max_tokens=self.max_tokens,
            system=system,
            messages=[{"role": "user", "content": user}],
        )

        text = response.content[0].text
        return LLMResponse(text=text, provider="anthropic", model=model)

    # ── 工具方法 ──────────────────────────────────────────────────────────────

    @staticmethod
    def _require_env(key: str) -> str:
        value = os.getenv(key, "").strip()
        if not value:
            raise RuntimeError(
                f"环境变量 {key} 未设置。请在 .env 文件中配置。"
            )
        return value
