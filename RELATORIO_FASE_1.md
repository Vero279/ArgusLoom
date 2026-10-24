# RELATÓRIO FASE 1

## Objetivo
A Fase 1 teve como objetivo validar a ingestão de infraestrutura em grafos para o MVP do ArgusLoom, cobrindo Terraform e Kubernetes e produzindo uma representação unificada de ativos e dependências.

## Entregáveis implementados
- Modelo de domínio do grafo com nós, arestas, enums de risco e STRIDE.
- Parser de Terraform para recursos AWS comuns.
- Parser de Kubernetes para manifestos de Deployment, Service, Ingress, Secret, ConfigMap e ServiceAccount.
- Montador de grafo unificado com persistência em JSON.
- Fixtures de teste para cenários representativos.

## Validações executadas
Foi executado o conjunto de testes específico da Fase 1:

```bash
cd "c:\Users\Verónica Couto\Documents\EngMul3.2\PROJETO_FINAL\00_NEW\VERONICA\Project\argusloom"; .\.venv\Scripts\python -m pytest tests/unit/test_terraform_parser.py tests/unit/test_k8s_parser.py tests/unit/test_graph_builder.py -q
```

Resultado verificado:
- 8 testes aprovados
- tempo: 0.42s

## Resultado
A ingestão da infraestrutura foi validada com sucesso para os cenários de entrada considerados, gerando um grafo estruturado com nós, arestas e risco inicial associado a exposição e criticidade.

## Observações
- A normalização de referências Terraform foi ajustada para lidar com interpolação do tipo `${aws_xxx.yyy.id}`.
- Os enums de criticidade foram compatibilizados com os nomes esperados pelos testes de aceite.

## Próximo passo
Prosseguir para a Fase 2, focada no enriquecimento do grafo com análise de ameaças e priorização de riscos.
