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
├── formatters/            # Camada de saída e serialização
├── cli/                   # Interface de linha de comando
├── web/                   # Interface web local para uso guiado
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
log → parser → evento → detector → resultado → formatter → CLI/Web
```

* O parser extrai informações do log
* O detector analisa o comportamento
* O resultado traz classificação + explicação
* O formatter transforma a análise em JSON estruturado ou texto legível
* A CLI e a interface web usam o mesmo core de análise

---

## ▶️ Como rodar

### 🔹 CLI local

```bash
pip install -r requirements.txt
python -m cli.main sample.log
```

Saída em texto para leitura humana:

```bash
python -m cli.main sample.log --format text
```

JSON indentado:

```bash
python -m cli.main sample.log --pretty
```

---

### 🔹 Interface web local

```bash
python -m web.app
```

Depois acesse:

```text
http://127.0.0.1:8080
```

A interface web roda localmente, usa apenas memória e não grava uploads, banco de dados ou arquivos temporários. Ela foi pensada para usuários menos acostumados com terminal: basta colar logs SSH/auth.log e clicar em analisar.

Para escolher host ou porta:

```bash
python -m web.app --host 127.0.0.1 --port 8080
```

---

## 🧹 Higiene de cache e disco

O projeto evita gerar artefatos persistentes durante a execução:

* A CLI e a interface web ativam `dont_write_bytecode`.
* Ao iniciar, o app remove `__pycache__` e arquivos `.pyc` dentro do projeto.
* Ao encerrar a interface web, a limpeza roda novamente.
* A interface web processa o texto em memória; nada é salvo em disco.

Isso ajuda a manter o repositório limpo e reduz crescimento desnecessário em ambientes com pouco espaço.

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
* Evoluir a interface web local
* Adicionar camada de explicação mais rica

---

## ☁️ Visão futura

A ideia é evoluir isso para:

* Rodar em container (Docker)
* Ter integração com cloud (AWS, GCP)
* Usar Cloudflare como camada de edge para demonstração
* Evoluir para dashboard web com visão histórica e filtros

---

## 💡 Por que estou fazendo isso

Esse projeto também faz parte da minha transição e consolidação em:

* Segurança (Blue Team)
* Cloud
* Arquitetura de sistemas
* Aplicação prática de IA

Quero construir algo que seja útil de verdade — não só um projeto de portfólio, mas uma ferramenta que eu mesmo usaria.

---
