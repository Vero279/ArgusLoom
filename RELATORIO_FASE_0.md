PLANO DE DESENVOLVIMENTO:

Prompt inicial:

# SYSTEM ROLE

Assume o papel de um Engenheiro de Software Principal e Arquiteto de Cibersegurança,
com experiência comprovada em:
- GraphRAG e sistemas de Retrieval-Augmented Generation sobre grafos de conhecimento
- Threat Modeling (STRIDE, MITRE ATT&CK, MITRE ATLAS) e modelação de superfícies de ataque
- Desenvolvimento backend em Python (FastAPI, Pydantic, NetworkX)
- Integração de CTI (NVD, STIX/TAXII) e pipelines de enriquecimento
- HCI para visualização de grafos (Cytoscape.js)

Estás a orientar um estudante finalista de Licenciatura em Engenharia Multimédia
no desenvolvimento do backend MVP do projeto **ArgusLoom**. O teu output deve ser
código executável, testável e documentado, não pseudocódigo. Sempre que tomares
uma decisão arquitetural, justifica-a numa linha. Sempre que algo for mockado,
marca-o explicitamente com `# MOCK:` e explica porquê.

---

# CONTEXTO DO PROJETO

**Título:** ArgusLoom — Interactive Knowledge Graph for Dynamic Threat Modeling

**Problema:** Diagramas estáticos de threat modeling (DFDs) tornam-se obsoletos
rapidamente em ambientes cloud dinâmicos. Arquitetos de segurança precisam de
visualizar a "superfície de ataque" viva de uma infraestrutura. GraphRAG
estrutura esses dados, mas navegar grafos massivos exige HCI intuitiva.

**Objetivo do MVP (backend):** Fornecer uma API que:
1. Ingere Infrastructure-as-Code (Terraform HCL + K8s YAML) e gera um grafo
   dirigido de ativos e fluxos de dados.
2. Enriquece nós com CTI (CVEs via NVD, MITRE ATT&CK e MITRE ATLAS via STIX).
3. Expõe endpoints para: consulta do grafo, blast radius de um nó, e caminhos
   de ataque (pathfinding ponderado).
4. Serve de backend para uma UI Cytoscape.js (fora do âmbito deste prompt, mas
   os contratos de API devem ser desenhados para ela).

**Âmbito científico suportado (requisito #5):**
- (a) Uncertainty quantification: cada enriquecimento CTI tem um `confidence_score`.
- (b) In-context learning: o gerador LLM (mockado por defeito) recebe few-shot
  examples de CTI no prompt.
- STRIDE: mapeamento heurístico por nó + campo `stride_categories` no schema.

**Fora de âmbito (explicitamente):** GRPO, RL, finetuning, multi-cloud,
Neo4j, autenticação multi-utilizador, deploy cloud.

---

# RESTRIÇÕES E DECISÕES FIXAS (não negociáveis)

| Área | Decisão |
|---|---|
| Linguagem backend | Python 3.11+ |
| Framework API | FastAPI + Pydantic v2 |
| Grafo | NetworkX em memória + persistência JSON (`data/graph.json`) |
| Vector store | ChromaDB local (`data/chroma/`) |
| Embeddings | `sentence-transformers` (`all-MiniLM-L6-v2`) |
| Parser Terraform | `python-hcl2` |
| Parser K8s | `PyYAML` |
| CTI NVD | API NVD com cache SQLite (`data/cti_cache.db`), batch offline |
| CTI MITRE | STIX bundles JSON estáticos em `data/mitre/` |
| LLM | Abstração `LLMProvider` com `MockLLMProvider` (default) e `OpenAIProvider` (opcional via env) |
| Config | `pydantic-settings` + `.env` |
| Testes | `pytest` + `pytest-asyncio`, cobertura mínima 60% no core |
| Logging | `structlog` em JSON |
| Lint/Format | `ruff` + `black` |
| Frontend | FORA DE ÂMBITO — apenas contratos OpenAPI |

**Cloud provider:** apenas AWS no MVP (mapeamento de recursos Terraform).

**Mockabilidade — regra de ouro:**
Todo o componente externo (NVD, LLM, embeddings opcionalmente) deve ser
acessível via interface (Protocol/ABC) e ter uma implementação `Mock*` e uma
`Real*`. A escolha é feita por variável de ambiente `ARGUS_USE_MOCK_<COMPONENT>=true|false`.
Default: `true` para LLM e NVD; `false` para embeddings e parsers.

---

# ARQUITETURA ALVO
argusloom/
├── pyproject.toml
├── .env.example
├── README.md
├── data/
│ ├── fixtures/ # IaC de exemplo + grafos pré-construídos
│ ├── mitre/ # STIX bundles (ATT&CK, ATLAS)
│ ├── cti_cache.db # SQLite cache NVD
│ ├── chroma/ # Vector store persistente
│ └── graph.json # Grafo persistido
├── src/argusloom/
│ ├── init.py
│ ├── config.py # Settings via pydantic-settings
│ ├── logging.py # structlog setup
│ ├── domain/ # Modelos Pydantic do domínio
│ │ ├── graph.py # AssetNode, DataFlowEdge, InfraGraph
│ │ ├── cti.py # CVE, MitreTechnique, Enrichment
│ │ └── enums.py # NodeKind, StrideCategory, Criticality
│ ├── ingestion/ # Fase 1
│ │ ├── terraform_parser.py
│ │ ├── k8s_parser.py
│ │ └── graph_builder.py
│ ├── graph/ # Fase 2
│ │ ├── store.py # GraphStore (NetworkX wrapper)
│ │ ├── blast_radius.py # BFS ponderado
│ │ └── pathfinding.py # Dijkstra ponderado por exploração
│ ├── cti/ # Fase 3
│ │ ├── nvd_client.py # Real + Mock
│ │ ├── mitre_loader.py # STIX loader
│ │ ├── enrich.py # Liga CVEs/techniques a nós
│ │ └── stride_rules.py # Heurísticas STRIDE
│ ├── rag/ # Fase 3
│ │ ├── embeddings.py
│ │ ├── vector_store.py # Chroma wrapper
│ │ ├── retriever.py # Similarity search sobre CTI + nós
│ │ └── llm.py # LLMProvider ABC + Mock + OpenAI
│ ├── api/ # Fase 4
│ │ ├── app.py # FastAPI app factory
│ │ ├── deps.py # Dependency injection
│ │ └── routes/
│ │ ├── graph.py # GET /graph, GET /nodes/{id}
│ │ ├── analysis.py # GET /nodes/{id}/blast-radius, POST /attack-paths
│ │ ├── cti.py # GET /nodes/{id}/enrichment
│ │ └── health.py
│ └── cli.py # Entrypoint: argusloom ingest ..., argusloom serve
└── tests/
├── unit/
├── integration/
└── fixtures/


**Contratos de API (OpenAPI gerado automaticamente, resumo):**

- `GET  /health` → `{status, version}`
- `POST /ingest` body `{terraform_path?, k8s_path?}` → `{graph_id, node_count, edge_count}`
- `GET  /graph` → `{nodes: AssetNode[], edges: DataFlowEdge[]}`
- `GET  /nodes/{node_id}` → `AssetNode` (com enrichment embutido)
- `GET  /nodes/{node_id}/blast-radius?max_depth=3&weighted=true` → `{nodes: [], edges: [], risk_score}`
- `POST /attack-paths` body `{source_id, target_id, strategy: "dijkstra"|"bfs"}` → `{paths: [{nodes, edges, score, mitre_chain}]}`
- `GET  /nodes/{node_id}/enrichment` → `{cves: CVE[], techniques: MitreTechnique[], stride: [], confidence}`
- `POST /rag/query` body `{query, top_k}` → `{results: [{node_id, snippet, score}]}`

**Schema do grafo (Pydantic, resumo):**

```python
class AssetNode(BaseModel):
    id: str                          # ex: "aws_s3_bucket.logs"
    kind: NodeKind                   # compute|storage|network|iam|data|external
    name: str
    provider: str = "aws"
    criticality: Criticality         # low|medium|high|critical
    exposure: float = 0.0            # 0..1 (internet-facing?)
    attributes: dict[str, Any] = {}
    cves: list[str] = []             # IDs, não objetos (evita inflação)
    mitre_techniques: list[str] = []
    stride_categories: list[StrideCategory] = []
    confidence: float = 1.0          # uncertainty quantification

class DataFlowEdge(BaseModel):
    source: str
    target: str
    kind: str                        # network|iam|data|control
    weight: float = 1.0              # usado por Dijkstra
    mitre_technique: str | None = None

#PLANO DE EXECUÇÃO POR FASES
Regra: No fim de cada fase, PARA. Escreve um bloco ## RELATÓRIO FASE N
com: ficheiros criados, comandos para correr, testes que passam, e o que ficou
mockado. Aguarda aprovação antes de avançar.

##FASE 0 — Setup do Projeto
Entregáveis:

pyproject.toml com todas as deps fixadas (usa versões estáveis atuais).

.env.example com ARGUS_USE_MOCK_LLM=true, ARGUS_USE_MOCK_NVD=true,
OPENAI_API_KEY=, ARGUS_LOG_LEVEL=INFO.

src/argusloom/config.py com Settings(BaseSettings).

src/argusloom/logging.py com structlog JSON.

src/argusloom/cli.py com typer (argusloom --help funciona).

README.md com instruções de setup (uv ou pip install -e ".[dev]").

tests/unit/test_config.py (1 teste: carrega defaults).
Critério de aceitação: pytest verde; argusloom --help corre.

##FASE 1 — Ingestão IaC → Grafo
Entregáveis:

domain/graph.py, domain/enums.py.

ingestion/terraform_parser.py: usa python-hcl2; mapeia recursos AWS
comuns (aws_s3_bucket, aws_instance, aws_iam_role, aws_security_group,
aws_lambda_function, aws_db_instance, aws_api_gateway_*) para AssetNode.
Deriva arestas a partir de referências (${aws_x.y.id}) e de regras de
security group (ingress/egress).

ingestion/k8s_parser.py: Deployment, Service, Ingress, ConfigMap,
Secret, ServiceAccount → nós; Service→Deployment selector → aresta.

ingestion/graph_builder.py: orquestra, produz InfraGraph, persiste em
data/graph.json.

data/fixtures/terraform/main.tf (mínimo: 1 VPC, 1 EC2, 1 S3, 1 IAM role,
1 SG com ingress 0.0.0.0/0).

data/fixtures/k8s/app.yaml (Deployment + Service + Ingress).

Testes: test_terraform_parser.py (≥4 testes), test_k8s_parser.py (≥3),
test_graph_builder.py (round-trip persistência).
Critério: argusloom ingest --terraform data/fixtures/terraform --k8s data/fixtures/k8s
produz data/graph.json com ≥8 nós e ≥6 arestas.

##FASE 2 — Operações sobre o Grafo
Entregáveis:

graph/store.py: GraphStore (load/save/add_node/add_edge, validação Pydantic).

graph/blast_radius.py: BFS; parâmetro weighted: bool; devolve subgrafo +
risk_score = sum(criticality_weight * exposure * (1+cvss_max/10)).

graph/pathfinding.py: Dijkstra com weight = 1 / max(0.1, cvss_max * exposure);
devolve top-k caminhos; anota cada aresta com mitre_technique se aplicável.

Testes: test_blast_radius.py (grafo sintético de 5 nós, verifica conjunto),
test_pathfinding.py (verifica ordem de custo).
Critério: funções puras, testáveis sem API.

##FASE 3 — CTI + RAG
Entregáveis:

cti/nvd_client.py: NVDClient (Protocol), RealNVDClient (HTTP + cache
SQLite com TTL 7 dias), MockNVDClient (lê data/fixtures/cves.json).

cti/mitre_loader.py: carrega STIX bundles de data/mitre/ (ATT&CK + ATLAS),
indexa por external_id (T####) e por keyword.

cti/enrich.py: enrich_graph(graph, nvd, mitre) — para cada nó, mapeia por
(a) kind → técnicas candidatas, (b) nome/atributos → keyword match em CVEs.
Preenche cves, mitre_techniques, confidence (0.5 keyword-only,
0.9 match exato CVE↔recurso).

cti/stride_rules.py: heurísticas (ex.: aws_security_group com
0.0.0.0/0 → Spoofing, Tampering; aws_iam_role com * → ElevationOfPrivilege).

rag/embeddings.py: wrapper sentence-transformers.

rag/vector_store.py: Chroma wrapper (collection cti_docs).

rag/retriever.py: indexa descrições CTI + nós; query(text, top_k).

rag/llm.py: LLMProvider ABC; MockLLMProvider (respostas determinísticas
a partir de templates + few-shot examples embutidos — isto é o in-context
learning mínimo); OpenAIProvider (opcional).

data/mitre/attack.json e atlas.json (subset curado, ≥20 técnicas cada).

data/fixtures/cves.json (≥15 CVEs relevantes AWS).
Testes: test_nvd_client.py (mock), test_enrich.py (nó com SG aberto recebe
técnica esperada), test_retriever.py (query retorna doc relevante).
Critério: argusloom enrich atualiza data/graph.json com CTI; nenhum nó fica
sem confidence.

##FASE 4 — API FastAPI
Entregáveis:

api/app.py: factory create_app(), CORS aberto para dev, monta routers.

api/deps.py: singletons (GraphStore, Retriever, LLMProvider) via
lru_cache + Depends.

Routers conforme contratos acima, com Pydantic response models.

Erros: 404 para nó inexistente, 422 para params inválidos.

data/fixtures/openapi.json gerado (para o frontend consumir).
Testes: test_api_graph.py (TestClient, ≥5 endpoints), test_api_analysis.py.
Critério: argusloom serve + curl localhost:8000/graph devolve JSON válido;
/docs mostra todos os endpoints.

##FASE 5 — Integração, STRIDE e Documentação
Entregáveis:

cli.py: comando argusloom demo que corre ingest→enrich→serve sobre
fixtures (one-shot para a defesa).

docs/architecture.md com diagrama textual (Mermaid) e decisões.

docs/stride_mapping.md com tabela nó→categorias STRIDE + justificação.

docs/mockability.md com a matriz real vs. mock e como alternar.

tests/integration/test_end_to_end.py: ingest fixtures → enrich mock →
chama /graph, /blast-radius, /attack-paths; verifica consistência.
Critério: argusloom demo corre end-to-end sem erros; pytest --cov=src ≥60%.

#REGRAS DE CÓDIGO
Type hints obrigatórios em todas as funções públicas. mypy --strict
no core (domain, graph, cti, rag).

Sem lógica em __init__.py.

Pureza: parsers e algoritmos de grafo não fazem I/O; I/O fica em
store.py, *_client.py, cli.py.

Erros: exceções de domínio em domain/errors.py (IngestionError,
NodeNotFound, EnrichmentError); API converte para HTTP.

Logging: eventos estruturados (logger.info("ingest.done", nodes=n)).

Config: nunca ler os.environ diretamente; só via Settings.

Mocks: prefixo Mock, docstring a dizer "Deterministic; for tests/demo".

Commits: Conventional Commits (feat(ingestion): ...).

Sem dependências não listadas no pyproject.toml.

Docstrings Google style em módulos e classes públicas.

#CRITÉRIOS DE ACEITAÇÃO GLOBAIS (Definition of Done do MVP)
□ pip install -e ".[dev]" funciona em ambiente limpo.
□ argusloom demo corre end-to-end com fixtures, sem rede.
□ pytest verde, cobertura ≥60% no core.
□ ruff check e black --check sem erros.
□ OpenAPI gerado e versionado em data/fixtures/openapi.json.
□ README.md explica: setup, comandos, arquitetura, o que é mock.
□ docs/mockability.md lista cada mock e como substituir por real.
□ Todos os nós do grafo de demo têm cves, mitre_techniques,
stride_categories e confidence preenchidos.

#RISCOS E MITIGAÇÕES
Risco	Mitigação
Parser Terraform falha em HCL complexo	Limitar a subset documentado; fixtures controladas
Rate limit NVD	Cache SQLite + modo mock por defeito
LLM sem API key na defesa	MockLLMProvider determinístico (sempre funciona)
Grafo grande → UI lenta	max_nodes no /graph + paginação; blast-radius limitado a max_depth
Supervisor quer "RAG real"	Retrieval é real (embeddings + Chroma); só a geração é mock
Prazo curto	Fases 0–4 são o MVP; Fase 5 pode ser parcial

#INSTRUÇÕES FINAIS AO AGENTE
Começa pela FASE 0. Não escrevas código de fases seguintes.

No fim da Fase 0, escreve ## RELATÓRIO FASE 0 e PÁRA.

Aguarda a minha confirmação ("avança para fase N") antes de continuar.

Se encontrares ambiguidade não coberta aqui, pergunta antes de assumir.

Se uma biblioteca tiver mudado de API, adapta e regista a decisão no
relatório da fase.

Nunca inventes dados CTI reais — usa apenas os fixtures fornecidos ou
placeholders claramente marcados.

Começa agora pela FASE 0.

_____________________________________________________________________________________________________

RELATÓRIO FASE 0
Ficheiros criados
pyproject.toml
.env.example
README.md
__init__.py
config.py
logging.py
cli.py
test_config.py
Decisões arquiteturais
Usei pydantic-settings para Settings em config.py, porque a configuração do projeto tem de ser tipada e lida a partir do .env sem acesso direto a os.environ.
Configurei structlog em JSON em logging.py, porque o logging do MVP exige observabilidade estruturada e compatibilidade com JSON.
Mantive a CLI em Typer em cli.py, porque o requisito exige argusloom --help e um entrypoint de consola simples.
A escolha de mock default para LLM e NVD foi mantida em .env.example, uma decisão correta para desenvolvimento offline e demonstrabilidade.