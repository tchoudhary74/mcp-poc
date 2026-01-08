/** Winston logger configuration for the Splunk MCP Server */

import winston from 'winston';
import { settings } from '../config.js';

/** Custom format for structured JSON logging */
const structuredFormat = winston.format.combine(
  winston.format.timestamp({ format: 'ISO' }),
  winston.format.errors({ stack: true }),
  winston.format.json()
);

/** Main logger instance */
export const logger = winston.createLogger({
  level: settings.logLevel.toLowerCase(),
  format: structuredFormat,
  defaultMeta: {
    service: 'splunk-mcp-server',
    version: settings.etlVersion,
  },
  transports: [
    new winston.transports.Console({
      // Use stderr to avoid interfering with MCP stdio transport
      stderrLevels: ['error', 'warn', 'info', 'debug'],
    }),
  ],
});

/** Create a child logger with a specific component name */
export function createChildLogger(component: string): winston.Logger {
  return logger.child({ component });
}

/** Log levels for reference */
export const LogLevels = {
  ERROR: 'error',
  WARN: 'warn',
  INFO: 'info',
  DEBUG: 'debug',
} as const;
