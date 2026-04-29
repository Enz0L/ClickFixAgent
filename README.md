# FOFA_Agent

A proof-of-concept ReAct agent built with LangGraph and LangChain to sharpen my skills with agentic workflows, tool use, and LLM orchestration.

The agent autonomously hunts for **ClickFix** attack infrastructure using the [Fofa](https://fofa.info) search engine, extracts malicious PowerShell payloads from discovered pages, and produces a structured threat intelligence report.

> **ClickFix** is a social-engineering technique where attackers display fake CAPTCHA / browser verification pages. A JavaScript snippet silently loads a malicious PowerShell command into the victim's clipboard (`navigator.clipboard.writeText(...)`), then instructs the victim to paste it into the Windows Run dialog (Win+R → Ctrl+V → Enter), triggering execution of an infostealer or loader.

---

## How it works

The agent follows a **ReAct loop** (Reason → Act → Observe) orchestrated by LangGraph:

```
HumanMessage
     │
     ▼
┌──────────────────┐
│  agent_reason    │◄────┐
│  (LLM + tools)   │     │
└────────┬─────────┘     │
         │               │
   tool_calls?           │
    ┌────┴────┐          │
   yes        no         │
    │          ▼         │
    │        END         │
    ▼                    │
┌──────┐                 │
│  act │─────────────────┘
└──────┘
```

At each step the LLM decides which tool to call based on the current state. The loop ends when the LLM produces a final response with no pending tool calls.

### Tools

| Tool | Description |
|---|---|
| `fofa_search` | Queries the Fofa API with a dork and returns raw JSON results |
| `fetch_url` | Performs a static HTTP GET on a candidate host (50 KB cap, no JS execution) |
| `extract_powershell` | Scans HTML/JS with 5 regex patterns to extract ClickFix payloads |
| `defang` | Neutralises URLs and IPs for safe sharing (`hxxp://`, `[.]`) |
| `write_report` | Writes the final markdown report to `reports/` |

### Agent workflow

1. Build a Fofa dork (e.g. `body="navigator.clipboard.writeText" && body="powershell"`)
2. Call `fofa_search` to discover candidate hosts
3. For each candidate (up to 5), call `fetch_url` to retrieve the page statically
4. Call `extract_powershell` to identify malicious commands
5. Call `defang` on all IOCs before including them in the report
6. Call `write_report` to persist the findings as a structured markdown document

### Output

A markdown report in `reports/` with five sections:
- Executive summary (date, dork, asset count, malware families)
- IOC table (defanged host / IP / port / title / server)
- Extracted PowerShell payloads (one fenced block per sample)
- Observed TTPs (MITRE ATT&CK references)
- Methodology

---

## Stack

| Component | Role |
|---|---|
| Python 3.11+ | Runtime |
| [uv](https://github.com/astral-sh/uv) | Package manager / venv |
| LangGraph | ReAct graph orchestration |
| LangChain | LLM abstractions and tool binding |
| langchain-openrouter | OpenRouter connector (model: `deepseek/deepseek-v4-flash`) |
| requests | HTTP client for Fofa API and page fetching |
| python-dotenv | Secret loading from `.env` |

---

## Installation

```bash
git clone <repo-url>
cd FOFA_Agent
uv sync
cp .env.example .env
```

Fill in `.env` with your credentials:

```dotenv
OPENROUTER_API_KEY=""   # https://openrouter.ai/keys
FOFA_EMAIL=""           # your Fofa account email
FOFA_KEY=""             # Fofa → Personal Center → API Key
```

---

## Usage

```bash
uv run main.py
```

The report is written to `reports/clickfix-<date>.md`.

> **Fofa free tier note:** limited to ~10 requests/minute and ~100 results max. Keep `size` small (default: 5) and avoid hammering the API.

---

## Project structure

```
FOFA_Agent/
├── .env.example    # environment variable template
├── .gitignore
├── pyproject.toml
├── main.py         # StateGraph + entry-point
├── nodes.py        # LLM nodes + system prompt
├── react.py        # tools + LLM configuration
└── reports/        # generated at runtime (gitignored)
```

---

## Security & OPSEC

- All analysis is **static only** — no extracted command is ever executed.
- All IOCs in the report are **defanged** before output.
- Run the agent from a disposable VM or behind a proxy — ClickFix operators may log incoming requests.
- The `reports/` directory is gitignored; treat its contents as sensitive.

---

## Disclaimer

This tool is intended for **defensive threat intelligence** only (alerting providers, sharing IOCs with the community, tracking kit evolution). Do not use it to interact with or attack any infrastructure.
