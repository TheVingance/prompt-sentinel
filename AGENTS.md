# 🤖 AGENTS.md - Regras e Boas Práticas para Desenvolvimento com IA

Este documento define os padrões de engenharia, conduta e fluxo de trabalho para qualquer assistente de inteligência artificial (e desenvolvedores humanos) que colabore neste repositório.

---

## 🌿 1. Fluxo de Trabalho Git & Estratégia de Branches (Mandatório)

> **Regra Fundamental de Proteção:** É estritamente proibido desenvolver ou commitar código diretamente na branch `main`!

1. **Criação de Branch por Funcionalidade:**
   - A cada nova funcionalidade, correção de bug ou refatoração, **DEVE-SE** criar uma branch isolada a partir da `main`:
     - `feature/<nome-da-feature>`: para novas capacidades (ex: `feature/docker-compose-setup`, `feature/pii-masking`).
     - `fix/<nome-do-bug>`: para correção de problemas (ex: `fix/fastembed-leak`).
     - `perf/<otimizacao>`: para melhorias de latência ou throughput.
     - `test/<suite>`: para expansão de testes e benchmarks.
2. **Ciclo de Desenvolvimento Seguro:**
   - Todo o ciclo (implementação, testes, validação) ocorre na branch específica.
   - Apenas após os testes passarem e a funcionalidade estar validada, a branch é mesclada (*merge* ou *Pull Request*) para a `main`.
   - Isso garante que a `main` permaneça sempre estável, funcional e pronta para deploy a qualquer momento.
3. **Descrição Completa e Estruturada em Pull Requests:**
   - Todo link de criação de PR fornecido ao desenvolvedor **DEVE VIR ACOMPANHADO** de uma descrição detalhada em Markdown pronta para ser utilizada no GitHub, contendo:
     - Resumo claro do que foi desenvolvido e justificativa de segurança.
     - Mapeamento com o **OWASP Top 10 for LLMs**.
     - Lista dos componentes e arquivos afetados.
     - Evidência dos testes automatizados (`pytest`) e checagens de lint (`ruff`).
     - Métricas de impacto (latência, bloqueios, consumo de memória).

---

## 📋 2. Plano de Implementação & Aprovação Prévia Obrigatória

> **Gatilho de Bloqueio:** Nenhuma linha de código deve ser desenvolvida ou modificada para uma nova feature sem a apresentação do plano e o consentimento explícito do usuário.

1. **Criação do Artefato de Planejamento:**
   - Antes de iniciar qualquer nova funcionalidade ou alteração arquitetural, o agente **DEVE OBRIGATORIAMENTE** criar um artefato intitulado **"Plano de Implementação"**.
   - O plano deve detalhar:
     - **Objetivo da Feature:** Problema resolvido e valor agregado ao portfólio.
     - **Arquitetura & Design:** Módulos, classes, funções e contratos de API (endpoints/schemas).
     - **Arquivos Impactados:** Lista precisa de novos arquivos e arquivos existentes que serão alterados.
     - **Plano de Testes:** Cenários de testes unitários e de integração que serão construídos (`pytest`).
     - **Métricas de Performance & Segurança:** Impacto esperado na latência e no pipeline defensivo.
2. **Aprovação do Desenvolvedor:**
   - O agente deve solicitar a revisão do plano pelo desenvolvedor.
   - **O desenvolvimento só tem início após a aprovação formal do usuário.**

---

## 🎯 3. Princípios Fundamentais de Engenharia

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

## 🧪 4. Qualidade de Código & Testes

- **TDD / Testes Obrigatórios:** Nenhuma regra de segurança, filtro de PII ou rota de API deve ser considerada concluída sem testes automatizados em `tests/`.
- **Framework de Teste:** `pytest` com `pytest-asyncio`.
- **Métricas de Performance:** Ao implementar gargalos ou otimizações críticas, meça o tempo de execução e documente o impacto (latência em milissegundos).

### 🔄 Protocolo de Autonomia de Testes e Auto-Cura (Self-Healing Loop)
> **Regra Fundamental de Execução:** *"Encontrou um problema? Corrija. Achou um bug? Resolva."*
- **Autonomia na Correção:** O Agente de IA possui autorização e autonomia para diagnosticar e sanar falhas técnicas, quebras de testes unitários ou de integração, regressões, avisos do linter (`ruff`) e incompatibilidades de ambiente/infraestrutura de forma contínua e autônoma.
- **Resolução Sem Paradas Desnecessárias:** Diante de erros detectados durante a execução de testes ou compilação, o Agente **NÃO DEVE** interromper o fluxo operacional para pedir permissão sobre correções de bugs técnicos evidentes. Deve aplicar a correção cirúrgica, reexecutar a verificação e seguir até a validação plena da suíte de testes.

### 🛡️ Salvaguardas Críticas de Governança, Contenção e Segurança (Guardrails da Auto-Cura)
Para mitigar riscos de **alucinação em cascata**, **deriva arquitetural (*architectural drift*)** e **degradação silenciosa da segurança**, o Protocolo de Auto-Cura está subordinado aos seguintes controles inegociáveis:

1. **🚫 Anti-Tampering de Testes (Proibição de Suavização de Asserções):**
   - É **terminantemente proibido** contornar falhas alterando ou enfraquecendo asserções de testes para "forçar aprovação" (*Assertion Softening*).
   - É **proibido** deletar testes válidos, comentar blocos de teste ou aplicar decoradores como `@pytest.mark.skip` ou `@pytest.mark.xfail` sem autorização humana formal.
   - **A cura DEVE ocorrer na lógica do código produtivo (`src/`)**. Ajustes na pasta `tests/` são estritamente limitados à correção de tipagens, imports quebrados, nomes de classes atualizados ou fixtures incompatíveis decorrentes da evolução autorizada.

2. **⚡ Circuit Breaker de Auto-Cura (Limite Anti-Alucinação em Cascata):**
   - O loop autônomo possui um teto máximo de **3 iterações consecutivas de tentativa de cura** para a mesma falha ou grupo de falhas correlacionadas.
   - Se o problema não for sanado na 3ª iteração, ou se ocorrer um "efeito gangorra" (a correção do teste X quebrar os testes Y e Z), o circuito **DEVE ABRIR IMEDIATAMENTE**: o agente interrompe o loop, reverte para o último estado estável da branch, documenta a causa-raiz identificada e as tentativas realizadas, escalando a decisão para o desenvolvedor humano.

3. **🎯 Contenção Rígida do Raio de Explosão (*Blast Radius Containment*):**
   - **Escopo Cirúrgico:** Toda modificação corretiva deve restringir-se ao menor escopo possível necessário para resolver a falha.
   - **Inviolabilidade de Configurações de Qualidade:** É **proibido** desabilitar regras de lint no `pyproject.toml`, ignorar linters (`# noqa`, `# type: ignore`) de forma generalizada ou flexibilizar thresholds de segurança/performance para mascarar problemas.
   - **Inviolabilidade de Segredos e Dados:** Sob hipótese alguma uma ação de autocura pode criar credenciais hardcoded, desativar sanitizadores de PII ou alterar variáveis do `.env`.

4. **🚦 Gateways de Validação Estrita em CI/CD (*Quality Gates*):**
   - **100% Green Suite:** Apenas alterações que alcancem saída limpa (`exit code 0`) em 100% dos testes unitários e de integração são elegíveis para commit.
   - **Zero Linter Warnings:** `ruff check .` e `ruff format --check .` devem reportar 0 avisos e 0 erros.
   - **Sanidade de Contêineres:** Nenhuma correção é válida se inviabilizar o build limpo das imagens Docker ou a inicialização íntegra dos serviços dependentes.

5. **📜 Rastreabilidade e Transparência Operacional:**
   - Toda autocura realizada autonomamente deve ser explicitada no resumo da Pull Request ou resposta ao desenvolvedor, discriminando: **[Falha Identificada]**, **[Causa-Raiz Diagnosticada]** e **[Ação Corretiva Cirúrgica Aplicada]**.

---

## 📦 5. Commits Semânticos

Siga rigorosamente o padrão **Conventional Commits**:
- `feat(...)`: Nova funcionalidade.
- `fix(...)`: Correção de bug ou falha.
- `perf(...)`: Melhoria mensurável de desempenho.
- `test(...)`: Inclusão ou ajuste de testes.
- `docs(...)`: Atualização de documentação ou diagramas.
- `refactor(...)`: Refatoração interna sem alteração de comportamento público.

> **Regra de ouro:** Mensagens de commit devem ser escritas no imperativo, explicando o *porquê* e o *o quê*.

---

## 🐳 6. Reprodutibilidade & Docker

- Qualquer adição de dependência de sistema ou serviço (ex: novo banco, novo cache) **deve** ser refletida imediatamente no `docker-compose.yml` e no `Dockerfile`.
- O comando `docker compose up --build` deve funcionar na primeira tentativa em qualquer máquina limpa.

---

## 💬 7. Modos de Colaboração da IA com o Desenvolvedor

1. **Transparência nas decisões técnicas:** Ao sugerir uma biblioteca ou arquitetura, justifique o motivo (ex: por que FastEmbed em vez de SentenceTransformers completo).
2. **Alterações cirúrgicas:** Não reescreva módulos inteiros sem necessidade; preserve comentários explicativos e lógica estável existente.
3. **Foco no Portfólio:** Sempre estruture códigos com clareza visual, docstrings elucidativas e facilite a extração de métricas de impacto para o currículo.
