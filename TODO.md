# Splunk MCP Server - Development Roadmap

## Current POC Status

### Completed (POC Phase)

- [x] **Project Structure**
  - [x] Package.json with dependencies
  - [x] TypeScript configuration
  - [x] Environment configuration (.env.example)
  - [x] Git ignore

- [x] **Core Infrastructure**
  - [x] Configuration management (src/config.ts)
  - [x] Shared types + Zod schemas (src/types.ts)
  - [x] Winston logger (src/logging/logger.ts)
  - [x] Credential manager - env vars + AWS Secrets (src/credentials/credential-manager.ts)

- [x] **Splunk Client**
  - [x] REST API client (src/splunk/client.ts)
  - [x] Token authentication
  - [x] Session-based authentication (username/password)
  - [x] SSL verification toggle (for air-gapped environments)

- [x] **Security Layer**
  - [x] SPL injection detection (src/security/scanner.ts)
  - [x] Read-only enforcement (blocks DELETE, COLLECT, etc.)
  - [x] Prompt injection detection
  - [x] Input validation helpers (src/security/validators.ts)

- [x] **MCP Tools (8 total)**
  - [x] `splunk_search` - Execute SPL queries
  - [x] `splunk_get_events` - Retrieve events from indexes
  - [x] `splunk_correlate` - Find related events
  - [x] `splunk_get_context` - Get surrounding events
  - [x] `splunk_list_indexes` - Discover available indexes
  - [x] `splunk_list_saved_searches` - List saved searches
  - [x] `splunk_run_saved_search` - Execute saved searches
  - [x] `splunk_list_alerts` - View fired alerts

- [x] **Trust Scoring**
  - [x] 6-dimension trust evaluation
  - [x] Composite score calculation
  - [x] Threshold decisions (PROCEED, CAUTION, DON'T RELY)
  - [x] AI-readable directives

- [x] **Audit Logging**
  - [x] Tool call logging
  - [x] Security violation logging
  - [x] Sensitive data sanitization

- [x] **Documentation**
  - [x] README with quick start
  - [x] Claude Desktop config example

---

## Phase 2: Production Hardening

### Priority: High

- [ ] **Rate Limiting**
  - [ ] Per-tool rate limits
  - [ ] Token bucket algorithm
  - [ ] Configurable limits via environment

- [ ] **Connection Pooling**
  - [ ] Reuse HTTP connections
  - [ ] Connection health checks
  - [ ] Automatic reconnection

- [ ] **Error Handling Improvements**
  - [ ] Retry logic with exponential backoff
  - [ ] Circuit breaker pattern
  - [ ] Graceful degradation

- [ ] **Health Endpoints**
  - [ ] `/health` - Basic liveness
  - [ ] `/ready` - Readiness probe
  - [ ] Splunk connectivity status

- [ ] **Testing**
  - [ ] Unit tests for tools
  - [ ] Unit tests for security scanner
  - [ ] Integration tests with mock Splunk
  - [ ] End-to-end tests

### Priority: Medium

- [ ] **Caching**
  - [ ] In-memory cache for repeated queries
  - [ ] Cache TTL configuration
  - [ ] Cache invalidation

- [ ] **Metrics**
  - [ ] Query execution times
  - [ ] Tool usage counts
  - [ ] Error rates
  - [ ] Trust score distribution

- [ ] **Enhanced Logging**
  - [ ] Log rotation
  - [ ] Log file output (in addition to stderr)
  - [ ] Structured logging improvements

---

## Phase 3: Multi-User & Scaling

### Priority: High

- [ ] **Session Management**
  - [ ] Per-user sessions
  - [ ] Session timeout handling
  - [ ] Session storage (in-memory → Redis)

- [ ] **OAuth 2.0 Support**
  - [ ] OAuth token validation
  - [ ] Refresh token handling
  - [ ] Integration with identity providers

- [ ] **Role-Based Access Control (RBAC)**
  - [ ] Define roles (analyst, admin, etc.)
  - [ ] Tool-level permissions
  - [ ] Index-level restrictions

### Priority: Medium

- [ ] **Redis Integration**
  - [ ] Distributed cache
  - [ ] Session storage
  - [ ] Rate limit state

- [ ] **Database Integration**
  - [ ] Audit log persistence
  - [ ] Query history
  - [ ] User preferences

---

## Phase 4: Agent-to-Agent Communication

### Priority: High

- [ ] **WebSocket Transport**
  - [ ] WebSocket server implementation
  - [ ] Connection management
  - [ ] Heartbeat/ping-pong

- [ ] **HTTP Transport**
  - [ ] REST API endpoints
  - [ ] SSE for streaming results
  - [ ] Proper CORS handling

- [ ] **Message Queue Integration**
  - [ ] Async job processing
  - [ ] Job status tracking
  - [ ] Result retrieval

### Priority: Medium

- [ ] **Multi-Agent Orchestration**
  - [ ] Agent discovery
  - [ ] Agent registration
  - [ ] Load balancing

- [ ] **Streaming Results**
  - [ ] Stream large result sets
  - [ ] Progressive trust scoring
  - [ ] Chunked responses

---

## Phase 5: UI Frontend Integration

### Priority: High

- [ ] **API Gateway**
  - [ ] RESTful API for UI
  - [ ] WebSocket for real-time updates
  - [ ] Authentication middleware

- [ ] **Query Builder API**
  - [ ] SPL query assistance
  - [ ] Query validation endpoint
  - [ ] Query templates

- [ ] **Dashboard Data**
  - [ ] Recent queries endpoint
  - [ ] Alert summary endpoint
  - [ ] Trust score history

### Priority: Medium

- [ ] **Visualization Support**
  - [ ] Time series data formatting
  - [ ] Aggregation support
  - [ ] Chart-ready data structures

- [ ] **Export Features**
  - [ ] CSV export
  - [ ] JSON export
  - [ ] Report generation

---

## Phase 6: Enterprise Features

### Priority: High

- [ ] **Multi-Splunk Support**
  - [ ] Multiple Splunk instance configuration
  - [ ] Cross-instance queries
  - [ ] Instance health monitoring

- [ ] **Advanced Security**
  - [ ] Query allowlist/blocklist
  - [ ] Field-level masking
  - [ ] PII detection and redaction

- [ ] **Compliance**
  - [ ] Audit log export
  - [ ] Compliance reporting
  - [ ] Data retention policies

### Priority: Medium

- [ ] **High Availability**
  - [ ] Clustering support
  - [ ] Failover handling
  - [ ] Load balancing

- [ ] **Performance Optimization**
  - [ ] Query optimization suggestions
  - [ ] Parallel query execution
  - [ ] Result pagination

---

## Backlog / Nice-to-Have

- [ ] **Additional Tools**
  - [ ] `splunk_get_field_values` - Get distinct values for a field
  - [ ] `splunk_get_sourcetypes` - List available sourcetypes
  - [ ] `splunk_create_alert` - Create alert (with approval workflow)
  - [ ] `splunk_get_dashboard` - Retrieve dashboard data
  - [ ] `splunk_explain_query` - Explain SPL query

- [ ] **AI Enhancements**
  - [ ] Natural language to SPL conversion
  - [ ] Query suggestion based on context
  - [ ] Anomaly detection integration

- [ ] **Integration Options**
  - [ ] Slack notifications
  - [ ] PagerDuty integration
  - [ ] Jira ticket creation
  - [ ] ServiceNow integration

---

## Version History

| Version | Status | Description |
|---------|--------|-------------|
| 0.1.0   | ✅ Done | POC - Basic MCP server with 8 tools |
| 0.2.0   | 🔜 Next | Production hardening |
| 0.3.0   | Planned | Multi-user support |
| 0.4.0   | Planned | Agent-to-agent communication |
| 0.5.0   | Planned | UI frontend integration |
| 1.0.0   | Planned | Enterprise-ready release |

---

## Notes

- Current focus: **POC validation with Claude Desktop**
- Air-gapped environment considerations are built-in
- Trust scoring is a unique differentiator for AI safety
- Security is enforced at multiple layers (input validation → scanner → read-only)
