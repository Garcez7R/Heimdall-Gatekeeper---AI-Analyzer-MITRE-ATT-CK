# 🛡️ Heimdall Gatekeeper – AI Analyzer MITRE ATT&CK

O **Heimdall Gatekeeper** é um projeto que transforma logs de segurança em insights compreensíveis. Mais do que detectar, o foco aqui é **entender e explicar**.

A ideia não é criar mais um SIEM complexo, mas sim uma ferramenta leve que consiga analisar eventos, classificar riscos e explicar o que está acontecendo de forma clara — tanto para quem está começando quanto para quem já trabalha com segurança.

---

## 📌 Novidades da Versão (High Impact)
- **Agrupamento por IP**: Visualize ameaças consolidadas em vez de eventos repetidos.
- **Insights de Segurança**: Banners de alerta dinâmicos para ataques críticos detectados.
- **UI Aprimorada**: Destaques visuais em vermelho para eventos críticos e contadores de eventos por IP.
- **Arquitetura Modular**: Separação clara entre parsers, detectores e visualização.

---

## 🧱 Estrutura do Projeto

```text
.
├── core/
│   ├── analyzer.py         # Lógica de análise e agrupamento
│   └── models.py           # Contratos de dados centrais
├── parsers/
│   └── ssh_parser.py       # Parser para logs de SSH
├── detectors/
│   └── failed_login_detector.py # Lógica de detecção de falhas
├── web/
│   └── app.py              # Interface Web (Heimdall UI)
├── cli/
│   └── main.py             # Interface de linha de comando
├── requirements.txt        # Dependências Python
├── Dockerfile              # Configuração da imagem Docker
├── docker-compose.yml      # Orquestração local
├── sample.log              # Arquivo de log para testes
└── README.md               # Documentação
```

---

## ▶️ Como Rodar

### 🔹 Interface Web (Recomendado)
Para uma análise visual e intuitiva:
```bash
python3 -m web.app
```
Acesse em seu navegador: `http://localhost:8080`

### 🔹 Interface CLI
Para processamento rápido via terminal:
```bash
python3 -m cli.main sample.log
```

### 🔹 Docker
```bash
docker-compose up --build
```

---

## 🔍 Como o sistema funciona

O fluxo é simples e eficiente:
```text
log → parser → evento → detector → resultado → agrupador → visualização (CLI/Web)
```

* O parser extrai informações do log.
* O detector analisa o comportamento e mapeia técnicas MITRE.
* O agrupador consolida múltiplos eventos por IP para evitar ruído.
* A interface exibe insights claros e ações recomendadas.

---

## 🪜 Próximos passos
- [ ] Adicionar detectores de Brute Force separados por protocolo.
- [ ] Incluir MITRE como objeto estruturado e banco de dados local.
- [ ] Criar uma API simples com FastAPI para consumo externo.
- [ ] Evoluir para dashboard web com visão histórica e filtros.

---

## 💡 Por que este projeto?
Este projeto consolida conhecimentos em:
* Segurança (Blue Team)
* Cloud & Docker
* Arquitetura de sistemas
* Aplicação prática de IA na análise de dados

---
Repositório Oficial: [Heimdall-Gatekeeper---AI-Analyzer-MITRE-ATT-CK](https://github.com/Garcez7R/Heimdall-Gatekeeper---AI-Analyzer-MITRE-ATT-CK)
