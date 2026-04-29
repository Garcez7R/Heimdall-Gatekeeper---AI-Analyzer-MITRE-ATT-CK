# 🛡️ Heimdall AI – Blueprint v3

O **Heimdall AI** é uma ferramenta de análise de logs com foco em segurança, detecção inteligente de eventos e mapeamento MITRE ATT&CK.

## 📌 Visão Geral

- **Detecção de eventos de segurança**: Identifica comportamentos anômalos em logs.
- **Classificação inteligente**: Categoriza eventos por nível de criticidade.
- **Mapeamento MITRE ATT&CK**: Associa eventos a técnicas conhecidas de ataque.
- **Explicação em linguagem humana**: Fornece clareza sobre o que ocorreu.
- **Arquitetura portátil**: Pronto para Docker e multicloud.

## 🧱 Estrutura do Projeto

```text
heimdall-ai/
├── core/
│   └── models.py           # Contratos de dados centrais
├── parsers/
│   └── ssh_parser.py       # Parser para logs de SSH
├── detectors/
│   └── failed_login_detector.py # Lógica de detecção de falhas
├── cli/
│   └── main.py             # Interface de linha de comando
├── requirements.txt        # Dependências Python
├── Dockerfile              # Configuração da imagem Docker
├── docker-compose.yml      # Orquestração local
├── sample.log              # Arquivo de log para testes
└── README.md               # Documentação
```

## ▶️ Como Rodar

### Localmente

Certifique-se de ter o Python 3.11+ instalado.

1. Instale as dependências:
   ```bash
   pip install -r requirements.txt
   ```

2. Execute o analisador:
   ```bash
   python -m cli.main sample.log
   ```

### Via Docker

1. Suba o container:
   ```bash
   docker-compose up --build
   ```

## 🚀 Próximos Passos

- Adicionar detectores de Brute Force separados.
- Incluir MITRE como objeto estruturado.
- Criar uma API com FastAPI.
- Integrar com Cloudflare Workers.
