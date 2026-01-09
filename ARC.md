# Splunk MCP – Enterprise Architecture (Initial Draft)

This document describes the **end-to-end architecture** for deploying a Splunk MCP server
and consuming it from **Claude Desktop** in an enterprise environment.

-----

## 1. Build & Deploy Flow (CI/CD → Kubernetes)

This shows how the MCP server code is built, containerized, and deployed.

```
┌──────────────────────┐
│ Developer / Git Repo │
└──────────┬───────────┘
           │  Push / PR merge
           v
┌──────────────────────┐
│ Jenkins Pipeline     │
│  - Gradle build      │
│  - npm ci / npm build│
└──────────┬───────────┘
           │  docker build
           v
┌──────────────────────┐
│ Container Image      │
│  node dist/index.js  │
└──────────┬───────────┘
           │  push
           v
┌──────────────────────┐
│ Internal Registry    │
│ (Artifactory/Docker) │
└──────────┬───────────┘
           │  deploy (Helm / manifest)
           v
┌──────────────────────────────┐
│ Rancher / Kubernetes Cluster │
│  - Deployment                │
│  - Service (ClusterIP)       │
│  - Ingress (TLS + routing)   │
└──────────┬───────────────────┘
           │  stable HTTPS URL
           v
┌──────────────────────────────────────────┐
│ https://mcp-splunk.<env>.company.com/mcp │
└──────────────────────────────────────────┘
```

-----

## 2. Runtime Flow (Claude Desktop → MCP → Splunk)

This shows how a user request flows at runtime.

```
┌─────────────────────────────┐
│ User on Claude Desktop      │
│ Settings → Connectors       │
│ Add Custom Connector (URL)  │
└──────────────┬──────────────┘
               │ HTTPS (MCP tool calls)
               v
┌────────────────────────────────────────┐
│ Ingress / API Gateway                  │
│  - TLS                                 │
│  - SSO / OAuth                         │
│  - Rate limiting / WAF                 │
└──────────────┬─────────────────────────┘
               │ forwards request
               v
┌────────────────────────────────────────┐
│ MCP Server (Node.js in Kubernetes)     │
│                                        │
│  - MCP tool definitions                │
│  - Policy & guardrails                 │
│    • allowed tools                     │
│    • index / time-range limits         │
│    • result-size limits                │
│  - Audit logging (user + action)       │
│  - Reads secrets from Vault/K8s Secret │
└──────────────┬─────────────────────────┘
               │ REST / HEC
               v
┌────────────────────────────────────────┐
│ Splunk Platform                        │
│  - Search Jobs / Results (REST API)    │
│  - (Optional) HEC for ingestion        │
└────────────────────────────────────────┘
```

-----

## 3. Key Enterprise Principles

- **No Splunk credentials on user machines**
- **Claude Desktop only knows the MCP HTTPS URL**
- **SSO happens at the gateway**, not in the desktop
- **MCP enforces authorization and guardrails**
- **Splunk access via service account or delegated auth**
- **Full audit trail for every MCP invocation**

-----

## 4. Why This Scales

- Single MCP deployment per environment (DEV / SYS / PROD)
- Centralized security, auditing, and token management
- Zero local setup for end users beyond adding the connector
- Works naturally with Claude Desktop’s remote MCP model

-----

*End of initial architecture draft*

-----

## Next Steps (Optional)

- Mermaid version for Confluence diagrams
- Security/RBAC appendix (Splunk roles + MCP rules)
- “POC vs Production” delta section
  
