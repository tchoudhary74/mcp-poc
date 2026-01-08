# Splunk MCP Server

A Model Context Protocol (MCP) server that enables Claude Desktop to query and analyze Splunk data with built-in security controls and trust scoring.

## Features

- **8 MCP Tools** for Splunk interaction:
  - `splunk_search` - Execute SPL queries
  - `splunk_get_events` - Retrieve events from indexes
  - `splunk_correlate` - Find related events
  - `splunk_get_context` - Get surrounding events
  - `splunk_list_indexes` - Discover available indexes
  - `splunk_list_saved_searches` - List saved searches/reports
  - `splunk_run_saved_search` - Execute saved searches
  - `splunk_list_alerts` - View fired alerts

- **Security Features**:
  - SPL injection detection
  - Read-only enforcement (no DELETE, COLLECT, etc.)
  - Prompt injection detection
  - Input validation and sanitization

- **Trust Scoring**:
  - 6-dimension trust evaluation (authority, freshness, completeness, coherence, integrity, track record)
  - AI-readable directives (PROCEED, CAUTION, DON'T RELY)
  - Helps AI make informed decisions about data quality

- **Flexible Authentication**:
  - Environment variables (primary)
  - AWS Secrets Manager (optional)

## Quick Start

### 1. Install Dependencies

```bash
cd splunk-mcp-poc
npm install
```

### 2. Configure Environment

```bash
cp .env.example .env
```

Edit `.env` with your Splunk details:

```bash
# Required
SPLUNK_HOST=https://your-splunk:8089
SPLUNK_TOKEN=your-auth-token

# OR use username/password
# SPLUNK_USERNAME=admin
# SPLUNK_PASSWORD=your-password

# For self-signed certs (common in air-gapped environments)
SPLUNK_VERIFY_SSL=false
```

### 3. Build

```bash
npm run build
```

### 4. Configure Claude Desktop

Add to your Claude Desktop config (`~/Library/Application Support/Claude/claude_desktop_config.json` on macOS):

```json
{
  "mcpServers": {
    "splunk": {
      "command": "node",
      "args": ["/path/to/splunk-mcp-poc/dist/index.js"],
      "env": {
        "SPLUNK_HOST": "https://your-splunk:8089",
        "SPLUNK_TOKEN": "your-auth-token",
        "SPLUNK_VERIFY_SSL": "false"
      }
    }
  }
}
```

### 5. Restart Claude Desktop

The Splunk tools will now be available in Claude Desktop.

## Example Usage

Once connected, you can ask Claude:

- "List available Splunk indexes"
- "Search for failed login attempts in the last hour"
- "Show me the most recent security alerts"
- "Find events related to host web-server-01"
- "Run the 'Daily Security Report' saved search"

## Configuration Options

| Environment Variable | Description | Default |
|---------------------|-------------|---------|
| `SPLUNK_HOST` | Splunk REST API URL | Required |
| `SPLUNK_TOKEN` | Bearer token for auth | - |
| `SPLUNK_USERNAME` | Username for session auth | - |
| `SPLUNK_PASSWORD` | Password for session auth | - |
| `SPLUNK_APP` | Default Splunk app | `search` |
| `SPLUNK_VERIFY_SSL` | Verify SSL certificates | `true` |
| `SPLUNK_TIMEOUT` | Connection timeout (ms) | `30000` |
| `MAX_RESULTS` | Default max results | `1000` |
| `LOG_LEVEL` | Logging level | `info` |
| `TRUST_THRESHOLD_PROCEED` | Trust score for PROCEED | `0.7` |
| `TRUST_THRESHOLD_CAUTION` | Trust score for CAUTION | `0.4` |

## Development

```bash
# Type check
npm run type-check

# Build
npm run build

# Run development mode (with tsx)
npm run dev

# Watch mode
npm run watch
```

## Project Structure

```
src/
├── index.ts                 # Entry point
├── server.ts                # MCP server implementation
├── config.ts                # Configuration management
├── types.ts                 # TypeScript types + Zod schemas
├── credentials/
│   └── credential-manager.ts
├── splunk/
│   ├── auth.ts              # Authentication
│   ├── client.ts            # REST API client
│   └── types.ts             # Splunk-specific types
├── tools/
│   ├── index.ts             # Tool registry
│   ├── search.ts            # splunk_search
│   ├── events.ts            # splunk_get_events
│   ├── correlate.ts         # splunk_correlate
│   ├── context.ts           # splunk_get_context
│   ├── indexes.ts           # splunk_list_indexes
│   ├── saved-searches.ts    # splunk_list/run_saved_search
│   └── alerts.ts            # splunk_list_alerts
├── security/
│   ├── scanner.ts           # Injection detection
│   └── validators.ts        # Input validation
├── trust/
│   └── etl-middleware.ts    # Trust scoring
└── logging/
    ├── logger.ts            # Winston logger
    └── audit.ts             # Audit logging
```

## Trust Scoring

Every search result includes trust metadata:

```json
{
  "trust": {
    "compositeScore": 0.85,
    "thresholdDecision": "PROCEED",
    "dimensions": {
      "authority": 0.9,
      "freshness": 0.8,
      "completeness": 0.9,
      "coherence": 1.0,
      "integrity": 0.85,
      "trackRecord": 0.9
    },
    "agentDirective": "PROCEED with confidence. Trust score: 0.85..."
  }
}
```

## Security

This server implements multiple security layers:

1. **Read-Only Enforcement**: Blocks destructive SPL commands
2. **Injection Detection**: Detects and blocks SPL injection attempts
3. **Prompt Injection Detection**: Protects against AI manipulation
4. **Input Validation**: Validates all parameters before use
5. **Audit Logging**: Records all operations for compliance

## License

MIT
