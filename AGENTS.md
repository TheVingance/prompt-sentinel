# 🤖 AGENTS.md - Regras e Boas Práticas para Desenvolvimento com IA

Este documento define os padrões de engenharia, conduta e fluxo de trabalho para qualquer assistente de inteligência artificial (e desenvolvedores humanos) que colabore neste repositório.

---

## 🎯 1. Princípios Fundamentais

1. **Segurança em Primeiro Lugar:**
   - Nunca injete segredos, tokens ou senhas em código fonte ou arquivos rastreados pelo git.
   - Sempre utilize `.env` para dados sensíveis e mantenha `.env.example` sincronizado.
   - Todo código de sanitização de segurança deve conter testes que simulem ataques reais (payloads de prompt injection, XSS, bypasses).

2. **Clean Code & Padrões Python Modernos:**
   - Versão mínima: **Python 3.12+**.
   - **Tipagem estrita obrigatória:** Todas as funções e classes devem utilizar *Type Hints* completos (`typing`, `collections.abc`).
   - Uso de **Pydantic V2** para validação de esquemas de entrada/saída e configurações (`BaseSettings`).
   - Siga **PEP 8**, formate com `ruff` ou `black`.

3. **Arquitetura Assíncrona & Baixa Latência:**
   - Este projeto é um proxy de alta performance. **NUNCA** utilize funções bloqueantes em rotas assíncronas (ex: nunca use `requests`, utilize `httpx.AsyncClient`).
   - Utilize drivers de banco assíncronos (`asyncpg` / `SQLAlchemy 2.0 Async`).
   - Mantenha conexões de banco e Redis reutilizadas em pools de conexão globais através de eventos de ciclo de vida (`lifespan`) do FastAPI.

---

## 🧪 2. Qualidade de Código & Testes

- **TDD / Testes Obrigatórios:** Nenhuma regra de segurança, filtro de PII ou rota de API deve ser considerada concluída sem testes automatizados em `tests/`.
- **Framework de Teste:** `pytest` com `pytest-asyncio`.
- **Métricas de Performance:** Ao implementar gargalos ou otimizações críticas, meça o tempo de execução e documente o impacto (latência em milissegundos).

---

## 📦 3. Git & Commits Semânticos

Siga rigorosamente o padrão **Conventional Commits**:
- `feat(gateway)`: Nova funcionalidade (ex: adiciona rate limit por IP).
- `fix(sanitizer)`: Correção de bug ou bypass em filtro.
- `perf(embeddings)`: Melhoria mensurável de desempenho.
- `test(injection)`: Inclusão ou ajuste de testes.
- `docs(readme)`: Atualização de documentação ou diagramas.
- `refactor(core)`: Refatoração que não altera comportamento público.

> **Regra de ouro:** Mensagens de commit devem ser escritas no imperativo em inglês ou português coerente, explicando o *porquê* e o *o quê*.

---

## 🐳 4. Reprodutibilidade & Docker

- Qualquer adição de dependência de sistema ou serviço (ex: novo banco, novo cache) **deve** ser refletida imediatamente no `docker-compose.yml` e no `Dockerfile`.
- O comando `docker compose up --build` deve funcionar na primeira tentativa em qualquer máquina limpa.

---

## 💬 5. Modos de Colaboração da IA com o Desenvolvedor

1. **Transparência nas decisões técnicas:** Ao sugerir uma biblioteca ou arquitetura, justifique o motivo (ex: por que FastEmbed em vez de SentenceTransformers completo).
2. **Alterações cirúrgicas:** Não reescreva módulos inteiros sem necessidade; preserve comentários explicativos e lógica estável existente.
3. **Foco no Portfólio:** Sempre estruture códigos com clareza visual, docstrings elucidativas e facilite a extração de métricas de impacto para o currículo.
