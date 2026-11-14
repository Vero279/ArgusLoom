# Adapters externos e modo mock

Esta página descreve os adapters presentes no código e os seus defaults. Os valores podem ser alterados por configuração; isso não significa que todos os adapters reais estejam operacionais.

## Matriz

| Integração | Implementação mock | Implementação real | Default e notas |
|---|---|---|---|
| LLM | `MockLLMProvider` | `OpenAIProvider` | Mock por omissão. O provider OpenAI está deliberadamente indisponível: mesmo com a dependência instalada, `complete()` lança `NotImplementedError`. |
| NVD | `MockNVDClient` | `RealNVDClient` | Mock por omissão; `ARGUS_USE_MOCK_NVD=false` seleciona o cliente real. A consulta real depende de conectividade e pode usar `NVD_API_KEY`. |
| Embeddings | Não há provider mock | `EmbeddingModel` com `sentence-transformers` | Modelo local utilizado pelo retrieval; o primeiro uso pode requerer descarregar os pesos. |
| Vetores | — | ChromaDB | Coleção local no caminho `data/chroma`; o endpoint de RAG reinicia e volta a indexar a coleção por consulta. |
| MITRE | Dados versionados locais | — | O loader lê os ficheiros locais `data/mitre/attack.json` e `data/mitre/atlas.json`. |
| Terraform/Kubernetes | — | Parsers do projeto | Parsers locais, sem adapter externo alternativo. |
| Grafo | — | Modelo em memória e ficheiros JSON | O grafo ativo é lido de `data/graph.json`. |

## Configuração

`.env.example` contém:

```env
ARGUS_USE_MOCK_LLM=true
ARGUS_USE_MOCK_NVD=true
ARGUS_ENVIRONMENT=development
NVD_CACHE_TTL_DAYS=7
NVD_API_KEY=
NVD_TIMEOUT_SECONDS=10
OPENAI_API_KEY=
ARGUS_LOG_LEVEL=INFO
```

Para selecionar o cliente NVD real, configura:

```env
ARGUS_USE_MOCK_NVD=false
NVD_API_KEY=...
```

O valor da chave é um segredo local e não deve ser guardado no repositório. A seleção do provider LLM real através de `ARGUS_USE_MOCK_LLM=false` não habilita completions nesta configuração: `OpenAIProvider` lança explicitamente `NotImplementedError`.

## Comportamento observado

- O endpoint `/rag/query` não pede uma resposta LLM por omissão (`include_llm_answer=false`); o frontend também envia esse valor. O endpoint produz hits através de embeddings e Chroma.
- Se um cliente enviar `include_llm_answer=true`, o backend seleciona o provider segundo a configuração. Com o mock, a resposta é determinística; com o provider OpenAI atual, a chamada falha explicitamente como não implementada.
- O endpoint `/cti/enrich` seleciona o client NVD conforme a configuração; os dados MITRE vêm dos ficheiros locais.
- O comando `argusloom demo` instancia diretamente `MockNVDClient` para gerar a demo, independentemente da seleção do adapter NVD da API.

## Efeito na execução

Os mocks permitem executar a parte de LLM/NVD sem depender de serviços remotos, embora embeddings continuem a depender do pacote e do modelo local. A escolha de mocks torna os dados e respostas reprodutíveis nos fluxos cobertos por essas implementações; não equivale a uma integração real de LLM, nem assegura que os resultados do cliente NVD real sejam idênticos.
