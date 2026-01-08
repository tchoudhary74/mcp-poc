/** MCP Server implementation */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  ErrorCode,
  McpError,
} from '@modelcontextprotocol/sdk/types.js';

import { SplunkClient } from './splunk/client.js';
import { getCredentials } from './credentials/credential-manager.js';
import { toolDefinitions, executeTool, toolExists } from './tools/index.js';
import { ETLMiddleware } from './trust/etl-middleware.js';
import { AuditLogger } from './logging/audit.js';
import { scanQuery } from './security/scanner.js';
import { createChildLogger } from './logging/logger.js';
import { settings, getSafeConfig } from './config.js';
import {
  SplunkMCPError,
  SecurityError,
  SplunkSearchResultSchema,
  TrustMetadata,
} from './types.js';

const logger = createChildLogger('mcp-server');

/**
 * MCP Server for Splunk integration.
 */
export class SplunkMCPServer {
  private server: Server;
  private splunkClient: SplunkClient | null = null;
  private etlMiddleware: ETLMiddleware;
  private auditLogger: AuditLogger;
  private isInitialized = false;

  constructor() {
    this.server = new Server(
      {
        name: 'splunk-mcp-server',
        version: settings.etlVersion,
      },
      {
        capabilities: {
          tools: {},
        },
      }
    );

    this.etlMiddleware = new ETLMiddleware();
    this.auditLogger = new AuditLogger();

    this.setupHandlers();
  }

  /**
   * Set up MCP request handlers.
   */
  private setupHandlers(): void {
    // Handle list tools request
    this.server.setRequestHandler(ListToolsRequestSchema, async () => {
      logger.debug('Listing tools');

      return {
        tools: toolDefinitions,
      };
    });

    // Handle call tool request
    this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
      const { name, arguments: args } = request.params;

      logger.info('Tool called', { toolName: name });

      // Log the tool call
      this.auditLogger.logToolCall(name, args || {});

      try {
        // Ensure client is initialized
        if (!this.splunkClient) {
          throw new McpError(
            ErrorCode.InternalError,
            'Splunk client not initialized. Call initialize() first.'
          );
        }

        // Check if tool exists
        if (!toolExists(name)) {
          throw new McpError(ErrorCode.MethodNotFound, `Unknown tool: ${name}`);
        }

        // Execute the tool
        const result = await executeTool(name, args, this.splunkClient);

        // Add trust metadata for search-type tools
        let trustMetadata: TrustMetadata | undefined;
        if (this.shouldComputeTrust(name, result)) {
          trustMetadata = this.computeTrustForResult(result);
        }

        // Log success
        this.auditLogger.logToolSuccess(name, {
          eventCount: this.getEventCount(result),
          trustScore: trustMetadata?.compositeScore,
        });

        // Return response
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  ...result as object,
                  trust: trustMetadata,
                },
                null,
                2
              ),
            },
          ],
        };
      } catch (error) {
        // Log the error
        const isSecurityError = error instanceof SecurityError;
        this.auditLogger.logToolError(
          name,
          error instanceof Error ? error : new Error(String(error)),
          isSecurityError
        );

        // Handle security errors specially
        if (error instanceof SecurityError) {
          const scanResult = args?.query ? scanQuery(args.query as string) : null;
          if (scanResult) {
            this.auditLogger.logSecurityViolation(
              name,
              (args?.query as string) || '',
              scanResult.risk,
              scanResult.issues.map((i) => i.description)
            );
          }
        }

        // Convert to MCP error
        if (error instanceof McpError) {
          throw error;
        }

        if (error instanceof SplunkMCPError) {
          throw new McpError(
            error.isSecurityError ? ErrorCode.InvalidRequest : ErrorCode.InternalError,
            error.message
          );
        }

        throw new McpError(
          ErrorCode.InternalError,
          error instanceof Error ? error.message : String(error)
        );
      }
    });
  }

  /**
   * Determine if trust should be computed for a result.
   */
  private shouldComputeTrust(toolName: string, result: unknown): boolean {
    const trustableTools = [
      'splunk_search',
      'splunk_get_events',
      'splunk_correlate',
      'splunk_get_context',
      'splunk_run_saved_search',
    ];

    if (!trustableTools.includes(toolName)) {
      return false;
    }

    // Check if result has events
    if (result && typeof result === 'object' && 'events' in result) {
      return true;
    }

    return false;
  }

  /**
   * Compute trust metadata for a result.
   */
  private computeTrustForResult(result: unknown): TrustMetadata | undefined {
    try {
      // Convert result to SplunkSearchResult format
      const resultObj = result as Record<string, unknown>;
      const events = resultObj.events as unknown[] || [];
      const metadata = resultObj.metadata as Record<string, unknown> || {};

      const searchResult = SplunkSearchResultSchema.parse({
        events,
        totalEvents: metadata.totalCount || events.length,
        returnedEvents: events.length,
        truncated: metadata.truncated || false,
        searchId: metadata.searchId || 'unknown',
        executionTimeMs: metadata.executionTimeMs || 0,
        error: undefined,
        aggregations: undefined,
      });

      return this.etlMiddleware.computeTrust(searchResult);
    } catch (error) {
      logger.warn('Failed to compute trust', {
        error: error instanceof Error ? error.message : String(error),
      });
      return undefined;
    }
  }

  /**
   * Get event count from a result.
   */
  private getEventCount(result: unknown): number | undefined {
    if (result && typeof result === 'object') {
      if ('events' in result && Array.isArray((result as { events: unknown[] }).events)) {
        return (result as { events: unknown[] }).events.length;
      }
      if ('alerts' in result && Array.isArray((result as { alerts: unknown[] }).alerts)) {
        return (result as { alerts: unknown[] }).alerts.length;
      }
      if ('indexes' in result && Array.isArray((result as { indexes: unknown[] }).indexes)) {
        return (result as { indexes: unknown[] }).indexes.length;
      }
      if ('savedSearches' in result && Array.isArray((result as { savedSearches: unknown[] }).savedSearches)) {
        return (result as { savedSearches: unknown[] }).savedSearches.length;
      }
    }
    return undefined;
  }

  /**
   * Initialize the server and Splunk client.
   */
  async initialize(): Promise<void> {
    if (this.isInitialized) {
      return;
    }

    logger.info('Initializing Splunk MCP Server', {
      config: getSafeConfig(),
    });

    // Get credentials
    const { credentials, source } = await getCredentials();
    logger.info('Credentials loaded', { source });

    // Create and initialize Splunk client
    this.splunkClient = new SplunkClient(credentials);
    await this.splunkClient.initialize();

    // Perform health check
    const healthy = await this.splunkClient.healthCheck();
    if (!healthy) {
      throw new Error('Splunk health check failed');
    }

    logger.info('Splunk connection verified');
    this.isInitialized = true;
  }

  /**
   * Start the MCP server.
   */
  async start(): Promise<void> {
    // Initialize first
    await this.initialize();

    // Create stdio transport
    const transport = new StdioServerTransport();

    // Connect server to transport
    await this.server.connect(transport);

    logger.info('MCP Server started');
  }

  /**
   * Get the audit logger for external access.
   */
  getAuditLogger(): AuditLogger {
    return this.auditLogger;
  }

  /**
   * Get the ETL middleware version.
   */
  getVersion(): string {
    return this.etlMiddleware.getVersion();
  }
}
