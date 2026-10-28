# IOC Workbench

**Área do portfólio:** [Cybersecurity](https://github.com/alefkaue#cybersecurity) · **Contexto:** Projeto pessoal

[![Tests](https://github.com/alefkaue/ioc-workbench/actions/workflows/tests.yml/badge.svg)](https://github.com/alefkaue/ioc-workbench/actions/workflows/tests.yml)

Normaliza e deduplica listas de indicadores para triagem de incidentes. Reconhece IPv4, IPv6, domínios, URLs HTTP(S) e hashes MD5/SHA-1/SHA-256. Preserva as linhas de origem para rastreabilidade. **Não consulta DNS nem serviços externos.**

## Demonstração

Python 3.11+; somente biblioteca padrão.

```console
git clone https://github.com/alefkaue/ioc-workbench.git
cd ioc-workbench
python ioc_workbench.py examples/indicators.txt
python -m unittest discover -s tests -v
```

O exemplo contém sete entradas: cinco indicadores únicos, uma duplicata e uma linha rejeitada. `EXAMPLE[.]ORG` e `example.org.` convergem para o mesmo domínio, com ambas as linhas em `source_lines`.

Saída JSON: `input_count`, `unique_count`, `duplicates`, `counts`, `indicators` e `rejected`. Código de saída: **0** sem rejeições, **1** com rejeições, **2** erro de arquivo/decodificação. Uma rejeição não impede processar as outras linhas.

## Regras de normalização

| Entrada | Tratamento |
| --- | --- |
| `example[.]org` | Restaura pontos e normaliza caixa do domínio |
| `hxxps[:]//example.org` | Restaura esquema HTTPS |
| Domínio Unicode | Codifica usando IDNA da biblioteca padrão |
| IPv6 | Usa representação comprimida |
| URL | Normaliza host, esquema e porta padrão; preserva caminho, query e fragmento |
| Hash hexadecimal | Converte para minúsculas e identifica pelo comprimento |

## Arquitetura e limites

`Uma entrada por linha → normalização → validação → deduplicação por tipo/valor → JSON`. Linhas vazias e comentários iniciados por `#` são ignorados. Não extrai indicadores de texto livre, e-mail, CSV ou documentos; não expande CIDR. Domínios não são validados contra uma Public Suffix List. URLs com credenciais, espaços, controles ou barras invertidas são rejeitadas. IDNA segue o codec do Python, sem promessa de equivalência entre todos os navegadores.

Reconhecer um indicador não significa que ele é malicioso. A ferramenta não calcula reputação, não visita URLs e não cria bloqueios. A restauração de indicadores ofuscados produz URLs comuns no JSON: trate relatórios como dados de investigação. Não carrega o conteúdo apontado por eles. A deduplicação mantém o relatório em memória.

Próxima evolução: entrada CSV com coluna de origem e exportação STIX com testes de interoperabilidade.

Projeto educacional independente, desenvolvido com assistência de IA. Todos os exemplos usam dados sintéticos. Licença MIT.
