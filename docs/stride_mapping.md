# Mapeamento STRIDE implementado

O código aplica STRIDE em dois pontos diferentes: o parser Terraform pode atribuir categorias diretamente a determinados recursos, e `analysis.threat_model` usa `STRIDE_DEFAULTS` quando um nó não tem categorias próprias. Os valores seguintes refletem o código atual; não são uma classificação exaustiva de ameaças.

## Defaults da análise por `NodeKind`

| `NodeKind` | Categorias STRIDE usadas como default |
|---|---|
| `network` | Information Disclosure, Tampering, Denial of Service |
| `data` | Tampering, Information Disclosure, Repudiation |
| `storage` | Information Disclosure, Tampering |
| `iam` | Spoofing, Elevation of Privilege |
| `compute` | Denial of Service, Elevation of Privilege |
| `external` | Information Disclosure |

Se `node.stride` estiver preenchido, a análise usa essas categorias em vez de recorrer aos defaults do tipo. Caso contrário, consulta `STRIDE_DEFAULTS`.

## Categorias atribuídas pelo parser Terraform

| Tipo de recurso | Categorias atribuídas |
|---|---|
| `aws_security_group` | Information Disclosure, Elevation of Privilege |
| `aws_db_instance` | Tampering, Information Disclosure |
| `aws_lambda_function` | Elevation of Privilege |
| Outros tipos tratados pelo parser | Lista vazia; aplicam-se os defaults por `NodeKind` durante a análise |

O parser associa o tipo AWS a um `NodeKind`; por exemplo, security groups e API Gateway são `network`, instâncias e Lambda são `compute`, bases de dados são `data` e buckets S3 são `storage`. O tipo de recurso e as categorias atribuídas são decisões heurísticas explícitas do parser.

## Exposição de recursos Terraform

O parser atribui valores heurísticos de `exposure` por tipo. Para `aws_security_group`, considera se existe conteúdo no atributo `ingress`; quando existe, define `0.8`, e quando não existe, `0.4`. O código não verifica se o CIDR é público ao determinar esse valor. Em separado, cria uma aresta `exposes` para `external.internet` quando encontra uma regra de ingress com `cidr_blocks`.

Outros valores implementados incluem `0.6` para API Gateway, `0.5` para EC2 (`aws_instance`), `0.7` para S3 (`aws_s3_bucket`) e `0.2` para os restantes tipos. Estes valores não substituem uma análise de regras de firewall nem devem ser interpretados como probabilidades.

## Limitações

- O mapeamento depende dos tipos e atributos explicitamente tratados nos parsers.
- As categorias por tipo são heurísticas; não expressam uma avaliação contextual completa de ameaça.
- O parser Terraform não deteta, através do cálculo de exposição do security group, se um CIDR permite acesso público; a criação da aresta `exposes` apenas verifica a presença de `cidr_blocks`.
- A análise não modela, por si só, vulnerabilidades zero-day, sequência temporal de eventos, identidade operacional completa ou todos os caminhos de abuso de API.
