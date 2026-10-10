from typing import Any, Optional, Union
from pydantic import BaseModel, Field


class ChatMessage(BaseModel):
    role: str = Field(..., description="Papel da mensagem: system, user, assistant")
    content: Union[str, list[dict[str, Any]]] = Field(..., description="Conteúdo textual ou multimodal")
    name: Optional[str] = None


class ChatCompletionRequest(BaseModel):
    model: str = Field(..., description="Identificador do modelo LLM (ex: gpt-4o, claude-3-5-sonnet, llama3)")
    messages: list[ChatMessage] = Field(..., min_length=1, description="Lista de mensagens de histórico e prompt")
    temperature: Optional[float] = Field(default=0.7, ge=0.0, le=2.0)
    top_p: Optional[float] = Field(default=1.0, ge=0.0, le=1.0)
    n: Optional[int] = Field(default=1, ge=1)
    stream: Optional[bool] = Field(default=False, description="Ativar streaming Server-Sent Events")
    max_tokens: Optional[int] = Field(default=None, gt=0)
    presence_penalty: Optional[float] = 0.0
    frequency_penalty: Optional[float] = 0.0
    user: Optional[str] = Field(default=None, description="Identificador único do usuário final para rate limit")


class ChatChoice(BaseModel):
    index: int
    message: ChatMessage
    finish_reason: Optional[str] = "stop"


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
