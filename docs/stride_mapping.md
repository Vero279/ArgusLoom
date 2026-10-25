# Mapeamento STRIDE



## Tabela `NodeKind` → `StrideCategory`



| NodeKind | Categorias STRIDE | Justificação |

|---|---|---|

| `network` | Spoofing, Tampering, Information Disclosure, Denial of Service | Ingress público permite spoofing, DoS, exposição |

| `data` | Tampering, Information Disclosure, Repudiation | Dados sensíveis |

| `storage` | Information Disclosure, Tampering | S3/buckets |

| `iam` | Spoofing, Elevation of Privilege | Credenciais, roles |

| `compute` | Denial of Service, Elevation of Privilege | Instâncias |

| `external` | Information Disclosure | Serviços externos |



> O código real em `analysis/threat_model.py` define `STRIDE_DEFAULTS` com estes valores em `NodeKind` e usa `stride` do grafo quando está presente; a tabela acima foi alinhada ao que existe no código e não ao enunciado genérico.



## Heurísticas aplicadas



- `aws_security_group` com `ingress` público (`0.0.0.0/0`) eleva `spoofing` e `tampering` por exposição de superfície de entrada.

- `aws_db_instance` e `aws_s3_bucket` inherit `information_disclosure` e `tampering` por conterem dados sensíveis ou armazenamento persistente.

- `aws_iam_role` e `ServiceAccount` implicam `spoofing`/`elevation_of_privilege` por atribuição de identidade e escopo de privilégio.

- `aws_instance`, `Deployment` e `StatefulSet` têm `denial_of_service` ou `elevation_of_privilege` por serem workload executáveis.

- `Ingress` e `Service` de rede são tratados como `network` e expõem pontos de entrada públicos.



## Limitações



O mapeamento STRIDE é heurístico e não cobre falhas de cadeia de produção, race conditions, vulnerabilidades zero-day, abuso de API sem endpoint exposto, ou ataques de configuração multi-cloud. Também não modela dependências temporais, contaminação de cache ou falhas de integração entre serviços que exigem contexto operacional mais rico.



## Referência a eixo científico



O requisito #5 do projeto materializa a uncertainty quantification mínima no campo `confidence` das findings e das arestas. Em termos práticos, a análise de risco não presume certezas absolutas: a pontuação e a confiança ajudam a distinguir evidência direta de inferência heurística, sem transformar a classificação STRIDE num modelo probabilístico completo.

