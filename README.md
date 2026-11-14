# ArgusLoom

ArgusLoom é uma aplicação de demonstração para modelação de ameaças e análise de risco sobre grafos de infraestrutura. O backend Python/FastAPI ingere recursos Terraform e Kubernetes, enriquece o grafo com informação CTI, calcula risco, blast radius e caminhos de ataque, e disponibiliza recuperação semântica. O frontend React apresenta o grafo, uma vista em lista acessível por teclado, detalhes dos nós e resultados das análises.

## Requisitos

- Python 3.11 ou superior.
- Node.js e npm para executar o frontend.
- As dependências Python incluem ChromaDB e `sentence-transformers`; o primeiro uso da recuperação semântica pode descarregar o modelo de embeddings.

## Instalação e execução

Na raiz do repositório, instala o backend e as dependências de desenvolvimento:

```powershell
python -m pip install -e ".[dev]"
Copy-Item .env.example .env
```

O ficheiro `.env` usa adapters mock por omissão para LLM e NVD. Para reconstruir o grafo base a partir das fixtures e imprimir um resumo:

```powershell
argusloom demo
```

Inicia a API em `http://127.0.0.1:8000`:

```powershell
argusloom serve
```

Com a API em execução, inicia o frontend num segundo terminal:

```powershell
Set-Location frontend
npm install
npm run dev
```

O dashboard fica disponível em `http://localhost:5173`. Para alterar a origem da API, define `VITE_API_BASE_URL` antes de iniciar Vite. Os detalhes de execução e a checklist de acessibilidade estão em [frontend/README.md](./frontend/README.md).

## Cenários de demonstração

Os grafos gerados são guardados em `data/graph_A.json`, `data/graph_B.json` e `data/graph_C.json`. O grafo ativo pela API é `data/graph.json`.

| Cenário | Origem | Nós / arestas no grafo gerado | Foco |
|---|---|---:|---|
| A — Terraform | `data/fixtures/scenarios/A_terraform_only/` | 16 / 23 | Recursos AWS e relações de infraestrutura |
| B — Kubernetes | `data/fixtures/scenarios/B_k8s_only/` | 15 / 7 | Workloads e relações Kubernetes |
| C — Híbrido | `data/fixtures/scenarios/C_hybrid/` | 42 / 51 | Recursos AWS e Kubernetes combinados |

Regenera os grafos com:

```powershell
python ingest.py --scenario A
python ingest.py --scenario B
python ingest.py --scenario C
```

Ativa um dos grafos já gerados para a API e o dashboard:

```powershell
argusloom scenario list
argusloom scenario C
```

Em ambiente de desenvolvimento, o cabeçalho do dashboard também permite listar e ativar cenários através da API. Estes endpoints estão protegidos por `ARGUS_DEV_MODE`; o modo de desenvolvimento é desativado por omissão quando `ARGUS_ENVIRONMENT` é `production` ou `prod`.

## Arquitetura e documentação

O backend está organizado em módulos de domínio, ingestão, grafo, análise, CTI, RAG, API e workflow. O frontend é uma aplicação separada em `frontend/`. Consulte:

- [Arquitetura e fluxo de dados](docs/architecture.md)
- [Adapters externos e modo mock](docs/mockability.md)
- [Mapeamento STRIDE implementado](docs/stride_mapping.md)

## API

A especificação OpenAPI interativa fica em `http://127.0.0.1:8000/docs`.

| Método | Endpoint | Comportamento |
|---|---|---|
| `GET` | `/health` | Estado e versão do serviço |
| `GET` | `/graph` | Grafo ativo em `data/graph.json` |
| `POST` | `/graph/analyze` | Findings de risco para o grafo enviado no corpo |
| `POST` | `/graph/remediation` | Plano de remediação para o grafo enviado |
| `GET` | `/nodes/{node_id}/blast-radius` | Nós e arestas alcançáveis; `max_depth` e `weighted` são configuráveis |
| `POST` | `/attack-paths` | Caminhos entre `source_id` e `target_id` |
| `POST` | `/rag/query` | Pesquisa semântica no grafo; `include_llm_answer` é falso por omissão |
| `POST` | `/cti/enrich` | Enriquecimento CTI do grafo enviado |
| `GET` | `/dev/scenarios` | Lista cenários gerados, apenas em modo de desenvolvimento |
| `GET` | `/dev/scenarios/current` | Identifica o cenário ativo, apenas em modo de desenvolvimento |
| `POST` | `/dev/scenarios/{scenario_id}/activate` | Ativa A, B ou C, apenas em modo de desenvolvimento |

Em `/attack-paths`, `dijkstra` devolve o único caminho de menor custo e ignora `top_k`; `yen` devolve até `top_k` caminhos simples estruturalmente distintos, ordenados por custo. O contrato completo dos campos está descrito na especificação OpenAPI.

## Testes e verificações

Instala as dependências de desenvolvimento com `python -m pip install -e ".[dev]"` e executa a suite:

```powershell
python -m pytest -q
```

Verificações de estilo:

```powershell
ruff check .
black --check .
```

As verificações de acessibilidade do frontend e as instruções para executar axe estão em [frontend/README.md](./frontend/README.md). O estado destas verificações depende do ambiente e deve ser confirmado ao executá-las; este README não declara um resultado de teste permanente.

## Limitações conhecidas

- O sistema modela os tipos de recursos e relações suportados pelos parsers atuais; não é um analisador completo de Terraform nem de Kubernetes.
- O provider LLM mock é determinístico. A classe `OpenAIProvider` está deliberadamente indisponível nesta configuração e lança `NotImplementedError`; instalar a dependência opcional não ativa completions reais.
- O cliente NVD real existe, mas o modo mock está ativo por omissão para manter as demos reprodutíveis e offline.
- Os endpoints `/graph/analyze` e `/graph/remediation` recebem o grafo no corpo do pedido; endpoints de blast radius e caminhos de ataque usam o grafo ativo persistido em `data/graph.json`.
- Autenticação, autorização, operação multi-cloud e garantias de produção não fazem parte do âmbito atual.
