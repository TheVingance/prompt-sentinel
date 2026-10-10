---
name: "Diretrizes de Desenvolvimento & Regras do Projeto"
description: "Boas práticas de engenharia, tipagem estrita, criação de feature branches e testes para o PromptSentinel"
trigger: always_on
---

# 🤖 Diretrizes do Projeto (PromptSentinel)

## 🌿 1. Fluxo Git & Feature Branches (Obrigatório)
- **Nunca commitar diretamente na branch `main`.**
- A cada nova tarefa ou funcionalidade, criar uma branch: `feature/<nome>`, `fix/<nome>` ou `test/<nome>`.
- Realizar validações e testes antes do merge para a branch principal.

## 🎯 2. Padrões de Código Python
- Versão: Python 3.12+.
- Tipagem estrita completa com Pydantic V2 e Type Hints.
- Arquitetura 100% assíncrona (`httpx.AsyncClient`, `asyncpg`, sem chamadas I/O bloqueantes).
- NUNCA expor segredos, tokens ou dados sensíveis no repositório.

## 🧪 3. Qualidade & Testes
- Toda rota, filtro de segurança e mecanismo de sanitização deve possuir testes automatizados (`pytest`).
- Respeitar Conventional Commits (`feat:`, `fix:`, `docs:`, `test:`, `perf:`).
- Manter o ambiente Docker Compose funcional e atualizado.
