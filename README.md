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
- As ligações CVE-nó são calculadas apenas por correspondência CPE 2.3, versão declarada e mapeamento produto-CPE verificado; a pesquisa textual de CVEs não cria associações.
- As versões do engine RDS e do runtime Lambda são atributos de serviços geridos; tratá-los como software instalado para correspondência CPE é uma hipótese de modelação, não uma afirmação sobre o sistema operativo ou os componentes internos do fornecedor. As tags de software EC2 também são declarações do fixture, não deteção de pacotes.
- Os endpoints `/graph/analyze` e `/graph/remediation` recebem o grafo no corpo do pedido; endpoints de blast radius e caminhos de ataque usam o grafo ativo persistido em `data/graph.json`.
- Autenticação, autorização, operação multi-cloud e garantias de produção não fazem parte do âmbito atual.

## Demonstração experimental LLM08 (em preparação)

A infraestrutura local isolada está em `infra/localstack/` e `infra/llm08/`. O Compose publica LocalStack apenas em `127.0.0.1:4566`; os dois diretórios Terraform fixam o endpoint S3 local. O código de injeção fica exclusivamente em `tests/integration/llm08/` e recusa endpoints não locais.

O caminho de ataque primário de demonstração usa as arestas no sentido guardado no grafo: `attached_to` vai do security group para o recurso; `depends_on` vai do consumidor para a dependência. O percurso é constrained pelos waypoints `aws_security_group.public`, `aws_instance.web`, `aws_lambda_function.handler`, `aws_lambda_function.processor` e `aws_db_instance.database`. A ligação direta do security group ao handler permanece uma entrada alternativa.

Os helpers para snapshots e re-indexação estão em `src/argusloom/cti/`; cache, scoring exato e cliente Ollama local estão em `src/argusloom/evaluation/`. A configuração versionada está em `experiments/matrix.yaml`; as tabelas podem ser agregadas por `python -m reports.metrics`.

**A matriz ainda não está pronta para execução.** `data/cti_snapshot_manifest.json` marca os fixtures MITRE como não elegíveis porque não têm proveniência de release. O snapshot NVD de `CVE-2018-16603` descreve FreeRTOS, não a instância de base de dados à qual o grafo fixture o associa. A execução fica bloqueada até haver snapshots curados com proveniência, um gold set de 30 perguntas, aprovação do prompt e seleção de `num_ctx` pelo piloto. O preflight pode ser verificado com:

```powershell
python -m experiments.preflight
```

### Descoberta local de CPE e CVEs (Stage A)

Plano aprovado, incluindo a decisão de manter a descoberta separada da escolha de versão:

1. A descoberta usa a API local do operador, nunca é executada por este repositório.
2. A etapa seguinte escolhe manualmente o mapeamento produto→CPE e a versão a declarar.
3. Não declarar versões nginx/postgresql no Terraform até essa escolha ser feita.
4. Lambda é aceite como inventário sem uma CPE candidata ou CVE de destino obrigatório.
5. A compatibilidade da fase C mantém `no_retrieval` como cenário reservado, mas não o implementa nesta etapa.

Nenhuma chamada NVD é feita automaticamente. Depois de instalar o projeto em modo editável (`python -m pip install -e .`), execute localmente a descoberta do dicionário CPE e, em seguida, as consultas pelos nomes CPE exatos gerados:

```powershell
python scripts\fetch_nvd_snapshots.py --discover-product nginx
python scripts\fetch_nvd_snapshots.py --discover-product postgresql
python scripts\fetch_nvd_snapshots.py --cpe-names data\nvd\candidate_cpe_names_nginx.txt
python scripts\fetch_nvd_snapshots.py --cpe-names data\nvd\candidate_cpe_names_postgresql.txt
python scripts\summarize_cpe_candidates.py
```

O programa usa páginas CVE de até 2.000 resultados e páginas do dicionário CPE de até 10.000, conforme a documentação oficial das [Vulnerability APIs](https://nvd.nist.gov/developers/vulnerabilities) e [Product APIs](https://nvd.nist.gov/developers/products). A consulta `cveIds` e a consulta de nome exato `cpeName` são modos separados; `cpeName` exige componentes part/vendor/product/version explícitos. Sem chave, o cliente limita a 5 pedidos por janela de 30 segundos; com `NVD_API_KEY`, limita a 50 por janela e envia a chave apenas no header. Respostas 403/429 são repetidas com `Retry-After` ou backoff.

As respostas são guardadas sem transformação em `data/nvd/snapshots/` e cada página recebe SHA-256 em `data/cti_snapshot_manifest.json`. Uma consulta já guardada é imutável: repetir exige `--refetch --manifest-version <versão-maior>`. `data/cpe_product_mappings.json` regista candidatos com snapshot/hash de origem e estado `pending`; a aprovação do mapeamento é manual. `data/cpe_version_candidates.json` contém apenas as versões candidatas já aprovadas para descoberta, não versões declaradas nos fixtures. O resumo é offline e mostra `NOT_FETCHED` até existir snapshot exato. Não executar a descoberta mantém o inventário e os snapshots atuais intactos.

O extra opcional `[experiments]` contém as dependências para CodeCarbon, LM-Polygraph, Checkov e boto3; não é necessário para executar a aplicação normal.
