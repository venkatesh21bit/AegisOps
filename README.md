# 🛡️ AegisOps

**AegisOps** is an advanced, autonomous Agentic Site Reliability Engineering (SRE) platform. It leverages AI, LangGraph, and a robust set of integrations (Kubernetes, Splunk, OpenTelemetry, Slack) to detect incidents, orchestrate automated remediations, and drastically reduce mean time to resolution (MTTR) while maintaining strict human-in-the-loop (HITL) safety boundaries for mutating actions.

---

## 🏗️ Architecture

AegisOps acts as an intelligent middleware connecting observability platforms to your infrastructure. When an anomaly is detected, the agent autonomously gathers context, evaluates procedural safety policies, and proposes a remediation graph.

```mermaid
graph TD
    %% Define Nodes
    Alerts[Alertmanager / Webhooks]
    AegisOps[AegisOps API Server]
    LangGraph[LangGraph Agent Core]
    Postgres[(PostgreSQL Checkpointer & Vector DB)]
    Redis[(Redis Procedural Memory)]
    K8s[Kubernetes Cluster]
    Splunk[Splunk Enterprise]
    OTel[OpenTelemetry Collector]
    Slack[Slack HITL Gateway]

    %% Connections
    Alerts -->|Triggers Incident| AegisOps
    AegisOps -->|Initializes Graph| LangGraph
    
    LangGraph <-->|Saves/Resumes State| Postgres
    LangGraph <-->|Evaluates Safety Policies| Redis
    
    LangGraph -->|Queries Logs/Metrics| Splunk
    LangGraph -->|Patches ConfigMaps| OTel
    LangGraph -->|Executes Read/Write Ops| K8s
    
    LangGraph -->|L3 Mutating Actions: Pause| Slack
    Slack -->|Approve/Deny via Smee/Webhook| AegisOps
```

---

## 🚀 Key Features

* **Autonomous Remediation**: The AI agent independently investigates root causes using observability logs (Splunk) and metrics.
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
Start the foundational dependencies (PostgreSQL, Redis, Splunk) and mock microservices (Payment, Auth, Inventory) via Docker Compose:

```bash
# In the root of the project
docker-compose up -d
```
*Wait for Splunk to initialize (it may take a few minutes).*

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

### 4. Environment Variables
Create a `.env` file in the root directory and configure the following variables:

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

### 5. Slack Webhook Configuration (Smee)
Because AegisOps pauses execution to wait for a Slack button click, your local machine needs to receive webhooks from Slack. We use [Smee](https://smee.io/) to securely bypass NAT without warning pages.

1. Open a new terminal and run:
   ```bash
   npx smee-client --url https://smee.io/aegisops --path /slack/interactions --port 8001
   ```
2. Go to your **Slack API App Dashboard** -> **Interactivity & Shortcuts**.
3. Set the **Request URL** to `https://smee.io/aegisops`.
4. Click **Save Changes**.

### 6. Running the API Server
Start the AegisOps FastAPI application on port 8001:

```bash
.venv\Scripts\python.exe -m aegisops.api.main
```

### 7. Simulating an Incident
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
