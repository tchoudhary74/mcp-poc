/** Entry point for Splunk MCP Server */

import { SplunkMCPServer } from './server.js';
import { validateConfig } from './config.js';
import { logger } from './logging/logger.js';

let server: SplunkMCPServer | null = null;

/**
 * Graceful shutdown handler.
 */
async function gracefulShutdown(signal: string): Promise<void> {
  logger.info(`Received ${signal}. Shutting down gracefully...`);

  try {
    if (server) {
      await server.getAuditLogger().flush();
      logger.info('Audit logs flushed successfully');
    }
  } catch (error) {
    logger.error('Error during shutdown', {
      error: error instanceof Error ? error.message : String(error),
    });
  }

  process.exit(0);
}

/**
 * Main entry point.
 */
async function main(): Promise<void> {
  try {
    // Validate configuration
    logger.info('Validating configuration...');
    validateConfig();
    logger.info('Configuration valid');

    // Create and start server
    server = new SplunkMCPServer();

    // Set up signal handlers
    process.on('SIGINT', () => gracefulShutdown('SIGINT'));
    process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));

    // Handle uncaught errors
    process.on('uncaughtException', (error) => {
      logger.error('Uncaught exception', {
        error: error.message,
        stack: error.stack,
      });
      gracefulShutdown('uncaughtException');
    });

    process.on('unhandledRejection', (reason) => {
      logger.error('Unhandled rejection', {
        reason: reason instanceof Error ? reason.message : String(reason),
      });
    });

    // Start the server
    await server.start();

    logger.info('Splunk MCP Server is running', {
      version: server.getVersion(),
    });
  } catch (error) {
    logger.error('Failed to start server', {
      error: error instanceof Error ? error.message : String(error),
      stack: error instanceof Error ? error.stack : undefined,
    });
    process.exit(1);
  }
}

// Run main
main();
