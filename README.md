# 🛡️ AegisOps

**AegisOps** is an advanced, autonomous Agentic Site Reliability Engineering (SRE) platform. It leverages AI, LangGraph, and a robust set of integrations (Kubernetes, Splunk, OpenTelemetry, Slack) to detect incidents, orchestrate automated remediations, and drastically reduce mean time to resolution (MTTR) while maintaining strict human-in-the-loop (HITL) safety boundaries for mutating actions.

---

## 🏗️ Architecture

AegisOps acts as an intelligent middleware connecting observability platforms to your infrastructure. When an anomaly is detected, the agent autonomously gathers context, evaluates procedural safety policies, and proposes a remediation graph.

```mermaid
graph TD
    %% Define Styles
    classDef api fill:#4FC3F7,stroke:#333,stroke-width:2px,color:#000;
    classDef agent fill:#81C784,stroke:#333,stroke-width:2px,color:#000;
    classDef core fill:#FFB74D,stroke:#333,stroke-width:2px,color:#000;
    classDef storage fill:#BA68C8,stroke:#333,stroke-width:2px,color:#fff;
    classDef external fill:#E0E0E0,stroke:#333,stroke-width:2px,color:#000;

    subgraph "External Trigger Sources"
        Alerts[Alertmanager / Webhooks]:::external
    end

    subgraph "AegisOps System"
        subgraph "API Layer"
            FastAPI[FastAPI Server]:::api
            WebhookRouter[Webhook Router]:::api
            SlackGateway[Slack Interactions Gateway]:::api
        end

        subgraph "Agent Core (LangGraph)"
            GraphBuilder[LangGraph Builder]:::agent
            GatedTools[Gated Tools Executor]:::agent
            Nodes[Execution Nodes]:::agent
            PolicyEngine[Semantic Firewall / Policy Engine]:::core
        end

        subgraph "Storage & Memory"
            Postgres[(PostgreSQL Checkpointer)]:::storage
            Redis[(Redis Procedural Memory)]:::storage
        end

        subgraph "Tools & Integrations"
            K8sClient[Kubernetes Client]:::core
            SplunkMCP[Splunk MCP Server]:::core
            OTelClient[OpenTelemetry Manager]:::core
            SlackNotifier[Slack Notifier]:::core
        end
    end

    subgraph "External Infrastructure"
        K8s[Kubernetes Cluster]:::external
        Splunk[Splunk Enterprise]:::external
        OTel[OpenTelemetry Collector]:::external
        SlackWorkspace[Slack Workspace]:::external
    end

    %% API Layer flows
    Alerts -->|Triggers Incident Webhook| WebhookRouter
    WebhookRouter -->|Initializes/Resumes Graph| GraphBuilder
    SlackWorkspace -->|HITL Approval/Denial| SlackGateway
    SlackGateway -->|Resumes Paused Graph| GraphBuilder

    %% Agent Core flows
    GraphBuilder <-->|Saves/Resumes State| Postgres
    GraphBuilder -->|Delegates| Nodes
    Nodes -->|Uses| GatedTools
    
    GatedTools -->|Evaluates Safety| PolicyEngine
    PolicyEngine <-->|Reads Rules| Redis

    %% Tools flows
    GatedTools -->|Uses| SplunkMCP
    GatedTools -->|Uses| K8sClient
    GatedTools -->|Uses| OTelClient
    GatedTools -->|L3 Actions Pause & Notify| SlackNotifier

    %% External System interactions
    SplunkMCP -->|Queries Logs/Metrics| Splunk
    K8sClient -->|Read/Write Pods & Deployments| K8s
    OTelClient -->|Patches ConfigMaps| OTel
    SlackNotifier -->|Sends Interactive Messages| SlackWorkspace
```

---

## 🚀 Key Features

* **Autonomous Remediation**: The AI agent independently investigates root causes using observability logs and metrics fetched dynamically through a **Splunk MCP (Model Context Protocol) Server** connected to Splunk Enterprise.
* **LangGraph State Management**: Complex, multi-step incident resolutions are checkpointed to PostgreSQL, ensuring no lost progress and seamless pausing.
* **Semantic Firewall**: All tool calls are intercepted by an in-memory policy engine that evaluates the safety of operations against pre-defined rules.
* **Human-in-the-Loop (HITL)**: For mutating level-3 (L3) actions (like restarting deployments or patching ConfigMaps), the graph pauses execution and dispatches an interactive Slack message for human approval before proceeding.
* **Dynamic OpenTelemetry Filtering**: AegisOps can autonomously mutate OTel ConfigMaps to strip redundant telemetry during high-volume incidents, saving cloud costs.

---

## 🛠️ Detailed Implementation & Setup Steps

Follow these instructions to run the entire AegisOps stack locally.

### 1. Prerequisites
Ensure you have the following installed:
- [Docker & Docker Compose](https://docs.docker.com/get-docker/)
- [Python 3.10+](https://www.python.org/downloads/)
- [Node.js](https://nodejs.org/) (for Smee webhook tunneling)
- [Kubectl](https://kubernetes.io/docs/tasks/tools/)
- A Slack Workspace with permissions to create an App.

### 2. Infrastructure Setup (Docker Compose)
Start the foundational dependencies (PostgreSQL, Redis) and mock microservices (Payment, Auth, Inventory) via Docker Compose:

```bash
# In the root of the project
docker-compose up -d
```

### 3. Splunk Enterprise Connection
Ensure you have an external instance of **Splunk Enterprise** running and accessible. AegisOps connects to Splunk via the **Splunk MCP** to run diagnostic searches during incidents. Generate a Splunk Admin Token and a Splunk HEC (HTTP Event Collector) Token for the agent to use.

### 3. Python Environment Setup
Create a virtual environment and install dependencies:

```bash
python -m venv .venv
# Activate (Windows)
.venv\Scripts\activate
# Activate (Mac/Linux)
source .venv/bin/activate

pip install -r requirements.txt
```

### 5. Environment Variables
Create a `.env` file in the root directory (or copy the provided `.env.example`) and configure the following variables:

```ini
POSTGRES_DB=aegisops_db
POSTGRES_USER=postgres
POSTGRES_PASSWORD=secretpassword
POSTGRES_HOST=localhost
POSTGRES_PORT=5432
REDIS_URL=redis://localhost:6379

GOOGLE_API_KEY=<your_gemini_or_llm_key>

SPLUNK_HOST=localhost
SPLUNK_PORT=8000
SPLUNK_TOKEN=<your_splunk_admin_token>
SPLUNK_HEC_TOKEN=<your_splunk_hec_token>

SLACK_BOT_TOKEN=<xoxb-your-bot-token>
SLACK_SIGNING_SECRET=<your_signing_secret>
SLACK_CHANNEL_ID=<your_channel_id>

KUBECONFIG=./kubeconfig.yaml
```

### 6. Slack Webhook Configuration (Smee)
Because AegisOps pauses execution to wait for a Slack button click, your local machine needs to receive webhooks from Slack. We use [Smee](https://smee.io/) to securely bypass NAT without warning pages.

1. Open a new terminal and run:
   ```bash
   npx smee-client --url https://smee.io/aegisops --path /slack/interactions --port 8001
   ```
2. Go to your **Slack API App Dashboard** -> **Interactivity & Shortcuts**.
3. Set the **Request URL** to `https://smee.io/aegisops`.
4. Click **Save Changes**.

### 7. Running the API Server
Start the AegisOps FastAPI application on port 8001:

```bash
.venv\Scripts\python.exe -m aegisops.api.main
```

### 8. Simulating an Incident
We have provided an automated script that breaks the `payment-service` pod in Kubernetes and subsequently triggers the webhook.

1. Open a new terminal and run:
   ```bash
   .venv\Scripts\python.exe scripts/alertmanager_webhook.py
   ```
2. You will see AegisOps wake up in the API server terminal, retrieve the logs, evaluate policies, and propose a Kubernetes deployment restart.
3. The graph will **PAUSE** and send an interactive message to your Slack channel.
4. Click **Approve** in Slack.
5. The Smee client will forward the click to your local server, the LangGraph checkpoint will resume, and the agent will execute the fix.

---

## 🤝 Contributing
Contributions are welcome! Please ensure all PRs include proper documentation updates and pass existing test suites.

## 📄 License
MIT License. See `LICENSE` for more information.
