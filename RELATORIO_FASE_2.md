# RELATÓRIO FASE 2

## Objetivo
A Fase 2 teve como foco o enriquecimento do grafo já ingestido para apoiar análise de risco e priorização de ativos. O objetivo principal foi transformar relações e metadados de infraestrutura em um conjunto de achados de ameaça que representassem riscos reais de exposição, dependência e impacto.

## Entregáveis implementados
- módulo de análise de ameaças em `argusloom.analysis`
- cálculo de risco por ativo com base em:
  - criticidade
  - tipo de nó
  - exposição
  - dependências e ligações do grafo
- inferência de ameaças STRIDE
- ordenação dos achados por risco descendente
- testes unitários de regressão para a lógica de priorização

## Validações executadas
Foi validado o conjunto de testes da Fase 2 com o comando:

```bash
cd "c:\Users\Verónica Couto\Documents\EngMul3.2\PROJETO_FINAL\00_NEW\VERONICA\Project\argusloom"; .\.venv\Scripts\python -m pytest tests/unit/test_phase2_threat_enrichment.py -q
```

Resultado verificado:
- 2 testes aprovados
- tempo: 0.05s

Também foi executada a suíte completa para confirmar que a Fase 1 e a Fase 2 não introduziram regressões:

```bash
cd "c:\Users\Verónica Couto\Documents\EngMul3.2\PROJETO_FINAL\00_NEW\VERONICA\Project\argusloom"; .\.venv\Scripts\python -m pytest -q
```

Resultado verificado:
- 11 testes aprovados
- tempo: 1.01s

## Resultado
A análise de risco do grafo foi validada com sucesso. Os ativos com maior exposição, criticidade e dependências relevantes passaram a receber pontuação e priorização de ameaças, permitindo preparar o base para etapas mais avançadas do MVP.

## Observações
- o risco é calculado de forma determinística e reproduzível a partir do grafo
- a inferência STRIDE considera o tipo de nó e dados já presentes no grafo
- a priorização cognitiva permanece consistente com a lógica de exposição e impacto de infraestrutura

## Próximo passo
Prosseguir para a Fase 3, centrada em enriquecimento com CTI/Intel e em capacidades de RAG sobre conhecimento externo e contexto de ameaças.
