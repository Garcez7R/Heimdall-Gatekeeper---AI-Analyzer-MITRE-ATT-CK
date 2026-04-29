# 🛡️ Heimdall AI

O Heimdall AI é um projeto que estou desenvolvendo com o objetivo de transformar logs de segurança em algo realmente útil e compreensível.

A ideia não é criar mais um SIEM complexo, mas sim uma ferramenta leve que consiga analisar eventos, classificar riscos e explicar o que está acontecendo de forma clara — tanto para quem está começando quanto para quem já trabalha com segurança.

---

## 🎯 Objetivo

Quero construir uma ferramenta que:

* Analisa logs de segurança (começando por SSH)
* Detecta comportamentos suspeitos
* Classifica eventos (normal, suspeito, crítico)
* Mapeia para o MITRE ATT&CK
* Explica o que aconteceu em linguagem simples

Mais do que detectar, o foco aqui é **entender e explicar**.

---

## 🧠 Filosofia do projeto

Estou seguindo alguns princípios bem claros:

* Simplicidade > complexidade
* Clareza > excesso de detalhe técnico
* Evolução gradual > tentar fazer tudo de uma vez
* Funcionar bem > parecer sofisticado

---

## 🧱 Estrutura atual

```text
heimdall-ai/
├── core/                  # Modelos e contratos centrais
├── parsers/               # Responsável por interpretar logs
├── detectors/             # Lógica de detecção de eventos
├── cli/                   # Interface de linha de comando
├── docs/                  # Documentação do projeto
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
└── README.md
```

---

## 🔍 Como o sistema funciona

O fluxo é simples por enquanto:

```text
log → parser → evento → detector → resultado
```

* O parser extrai informações do log
* O detector analisa o comportamento
* O resultado traz classificação + explicação

---

## ▶️ Como rodar

### 🔹 Local

```bash
pip install -r requirements.txt
python -m cli.main sample.log
```

---

### 🔹 Docker

```bash
docker-compose up --build
```

---

## 📌 Status atual

🚧 Em desenvolvimento (MVP)

O projeto ainda está na fase inicial. Estou focando em:

* Estrutura sólida
* Código simples e legível
* Evolução incremental (sem pular etapas)

---

## 🪜 Próximos passos

* Melhorar o parser de SSH
* Implementar detecção de brute force
* Estruturar melhor o mapeamento MITRE
* Criar uma API simples
* Adicionar camada de explicação mais rica

---

## ☁️ Visão futura

A ideia é evoluir isso para:

* Rodar em container (Docker)
* Ter integração com cloud (AWS, GCP)
* Usar Cloudflare como camada de edge para demonstração
* Possivelmente evoluir para uma versão com interface web

---

## 💡 Por que estou fazendo isso

Esse projeto também faz parte da minha transição e consolidação em:

* Segurança (Blue Team)
* Cloud
* Arquitetura de sistemas
* Aplicação prática de IA

Quero construir algo que seja útil de verdade — não só um projeto de portfólio, mas uma ferramenta que eu mesmo usaria.

---
