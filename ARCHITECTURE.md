# AegisOps Architecture Details

AegisOps is an autonomous Agentic Site Reliability Engineering (SRE) platform. This document provides a detailed overview of its architecture, core components, and external interactions.

## High-Level Architecture Diagram

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

## Component Breakdown

### 1. API Layer
- **FastAPI Server (`aegisops.api`)**: The main entry point for the application.
- **Webhook Router**: Receives incoming alerts (e.g., from Prometheus Alertmanager) and initiates the LangGraph execution.
- **Slack Gateway**: A specialized endpoint for receiving interactive callbacks from Slack (e.g., when a human approves or denies a mutating action via Smee).

### 2. Agent Core (LangGraph)
- **Graph Builder (`aegisops.agent.graph_builder`)**: Constructs the stateful execution graph for incident investigation and remediation.
- **Execution Nodes (`aegisops.agent.nodes`)**: Defines the steps the agent takes, such as retrieving logs, analyzing root causes, and formulating a remediation plan.
- **Gated Tools (`aegisops.agent.gated_tools`)**: A wrapper around tool execution that ensures sensitive operations go through the Semantic Firewall.
- **Semantic Firewall**: Evaluates tool calls against predefined safety policies (stored in Redis) to prevent unauthorized or unsafe infrastructure mutations.

### 3. Storage & Memory
- **PostgreSQL**: Used as a checkpointer for LangGraph state management. Allows complex operations to pause (e.g., waiting for human approval) and resume without losing context.
- **Redis**: Acts as the procedural memory store, holding the dynamic safety policies and configuration rules the Semantic Firewall checks against.

### 4. Tools & Integrations
- **Kubernetes Client (`aegisops.integrations.kubernetes`)**: Interacts directly with the K8s API to read cluster state or execute remediations (e.g., restarting a pod).
- **Splunk MCP (`aegisops.mcp.splunk`)**: Integrates with Splunk Enterprise using the Model Context Protocol to fetch diagnostic logs and metrics seamlessly.
- **OpenTelemetry Manager**: Dynamically manages OpenTelemetry Collector configurations, allowing the agent to throttle telemetry during high-volume incidents.
- **Slack Notifier**: Responsible for sending interactive Slack messages to request human-in-the-loop (HITL) approval for Level-3 (mutating) actions.
