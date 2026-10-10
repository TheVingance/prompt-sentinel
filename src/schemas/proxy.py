from typing import Any

from pydantic import BaseModel, Field


class ChatMessage(BaseModel):
    role: str = Field(..., description="Papel da mensagem: system, user, assistant")
    content: str | list[dict[str, Any]] = Field(..., description="Conteúdo textual ou multimodal")
    name: str | None = None


class ChatCompletionRequest(BaseModel):
    model: str = Field(..., description="Identificador do modelo LLM (ex: gpt-4o, claude-3-5-sonnet, llama3)")
    messages: list[ChatMessage] = Field(..., min_length=1, description="Lista de mensagens de histórico e prompt")
    temperature: float | None = Field(default=0.7, ge=0.0, le=2.0)
    top_p: float | None = Field(default=1.0, ge=0.0, le=1.0)
    n: int | None = Field(default=1, ge=1)
    stream: bool | None = Field(default=False, description="Ativar streaming Server-Sent Events")
    max_tokens: int | None = Field(default=None, gt=0)
    presence_penalty: float | None = 0.0
    frequency_penalty: float | None = 0.0
    user: str | None = Field(default=None, description="Identificador único do usuário final para rate limit")


class ChatChoice(BaseModel):
    index: int
    message: ChatMessage
    finish_reason: str | None = "stop"


class UsageInfo(BaseModel):
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0


class ChatCompletionResponse(BaseModel):
    id: str
    object: str = "chat.completion"
    created: int
    model: str
    choices: list[ChatChoice]
    usage: UsageInfo
