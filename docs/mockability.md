# Mockabilidade e dependências externas



## Matriz de componentes externos



| Componente | Real | Mock | Flag de config | Default |

|---|---|---|---|---|

| LLM (`rag/llm.py`) | `OpenAIProvider` | `MockLLMProvider` | `use_mock_llm` | mock |

| NVD (`cti/nvd_client.py`) | `RealNVDClient` | `MockNVDClient` | `use_mock_nvd` | mock |

| Embeddings (`rag/embeddings.py`) | `sentence-transformers` | — (sem fallback) | — | real |

| MITRE (`cti/mitre_loader.py`) | ficheiros locais curados | — | — | real |

| Ingestão | parsers reais | — | — | real |

| Grafo | NetworkX/in-memory | — | — | real |



## Como alternar cada flag



Exemplo de `.env`:



```env

ARGUS_USE_MOCK_LLM=true

ARGUS_USE_MOCK_NVD=true

ARGUS_LOG_LEVEL=INFO

```



Para ativar o modo real quando disponível:



```env

ARGUS_USE_MOCK_LLM=false

ARGUS_USE_MOCK_NVD=false

```



## O que está sempre real



- Parsers de Terraform e Kubernetes.

- Estrutura do grafo e persistência em JSON.

- Blast radius e pathfinding.

- Retrieval por embeddings com Chroma e `sentence-transformers`.



## O que está sempre mock



- LLM (`MockLLMProvider`) para respostas determinísticas.

- NVD (`MockNVDClient`) para demo e CI offline.



## Justificação



O modo mock é o default por ser mais adequado a um projeto de demonstração e dissertação: elimina rate limits, reduz variabilidade e garante reprodutibilidade em laboratório. A arquitetura permite alternar para fontes reais sem mudar o contrato de domínio, mas a opção default preserva estabilidade e transparência na defesa.



## Impacto na tese



No capítulo de metodologia, a parte "real" corresponde ao pipeline de ingestão, ao grafo, à análise de risco e ao retrieval semântico local. O LLM e o NVD são mocks por opção arquitetural para manter a experiência reproduzível, offline e controlada durante a validação do MVP e da prova de conceito.



## Dívida técnica remanescente



A mockabilidade está implementada e documentada, mas o projeto mantém dívida conhecida nos endpoints legados em `dict[str, Any]`, na ausência de retrofit Pydantic e na zona antiga de `analysis/`, `ingestion/` e testes F2–F5, que foi deixada intencionalmente fora do escopo da F9.

