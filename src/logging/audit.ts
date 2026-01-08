/** Audit logging for security and compliance */

import { settings } from '../config.js';
import { createChildLogger } from './logger.js';

const logger = createChildLogger('audit');

/** Audit event types */
export enum AuditEventType {
  TOOL_CALLED = 'tool_called',
  TOOL_SUCCESS = 'tool_success',
  TOOL_ERROR = 'tool_error',
  SECURITY_VIOLATION = 'security_violation',
  AUTH_SUCCESS = 'auth_success',
  AUTH_FAILURE = 'auth_failure',
  SEARCH_EXECUTED = 'search_executed',
  CONNECTION_ESTABLISHED = 'connection_established',
  CONNECTION_FAILED = 'connection_failed',
}

/** Audit event data */
export interface AuditEvent {
  type: AuditEventType;
  timestamp: Date;
  toolName?: string;
  query?: string;
  parameters?: Record<string, unknown>;
  result?: {
    success: boolean;
    eventCount?: number;
    executionTimeMs?: number;
    trustScore?: number;
  };
  error?: {
    code: string;
    message: string;
    isSecurityError?: boolean;
  };
  securityContext?: {
    riskLevel?: string;
    issues?: string[];
    blocked?: boolean;
  };
}

/** Audit log buffer for batch writing */
const auditBuffer: AuditEvent[] = [];
const BUFFER_FLUSH_INTERVAL = 5000; // 5 seconds
const MAX_BUFFER_SIZE = 100;

let flushTimer: NodeJS.Timeout | null = null;

/**
 * Log an audit event.
 */
export function logAuditEvent(event: Omit<AuditEvent, 'timestamp'>): void {
  if (!settings.enableAuditLog) {
    return;
  }

  const fullEvent: AuditEvent = {
    ...event,
    timestamp: new Date(),
    // Sanitize sensitive data
    query: event.query ? sanitizeQuery(event.query) : undefined,
    parameters: event.parameters ? sanitizeParameters(event.parameters) : undefined,
  };

  auditBuffer.push(fullEvent);

  // Log immediately for important events
  if (
    event.type === AuditEventType.SECURITY_VIOLATION ||
    event.type === AuditEventType.AUTH_FAILURE
  ) {
    flushAuditLog();
  } else if (auditBuffer.length >= MAX_BUFFER_SIZE) {
    flushAuditLog();
  } else {
    // Schedule flush if not already scheduled
    if (!flushTimer) {
      flushTimer = setTimeout(() => {
        flushAuditLog();
      }, BUFFER_FLUSH_INTERVAL);
    }
  }
}

/**
 * Flush the audit log buffer.
 */
export function flushAuditLog(): void {
  if (flushTimer) {
    clearTimeout(flushTimer);
    flushTimer = null;
  }

  if (auditBuffer.length === 0) {
    return;
  }

  // Log all buffered events
  for (const event of auditBuffer) {
    logger.info('audit_event', {
      type: event.type,
      timestamp: event.timestamp.toISOString(),
      toolName: event.toolName,
      query: event.query,
      result: event.result,
      error: event.error,
      securityContext: event.securityContext,
    });
  }

  // Clear buffer
  auditBuffer.length = 0;
}

/**
 * Convenience function to log a tool call.
 */
export function auditToolCall(
  toolName: string,
  parameters: Record<string, unknown>
): void {
  logAuditEvent({
    type: AuditEventType.TOOL_CALLED,
    toolName,
    parameters,
  });
}

/**
 * Convenience function to log a tool success.
 */
export function auditToolSuccess(
  toolName: string,
  result: {
    eventCount?: number;
    executionTimeMs?: number;
    trustScore?: number;
  }
): void {
  logAuditEvent({
    type: AuditEventType.TOOL_SUCCESS,
    toolName,
    result: {
      success: true,
      ...result,
    },
  });
}

/**
 * Convenience function to log a tool error.
 */
export function auditToolError(
  toolName: string,
  error: Error,
  isSecurityError = false
): void {
  logAuditEvent({
    type: isSecurityError ? AuditEventType.SECURITY_VIOLATION : AuditEventType.TOOL_ERROR,
    toolName,
    error: {
      code: (error as { code?: string }).code || 'UNKNOWN',
      message: error.message,
      isSecurityError,
    },
  });
}

/**
 * Convenience function to log a security violation.
 */
export function auditSecurityViolation(
  toolName: string,
  query: string,
  riskLevel: string,
  issues: string[]
): void {
  logAuditEvent({
    type: AuditEventType.SECURITY_VIOLATION,
    toolName,
    query,
    securityContext: {
      riskLevel,
      issues,
      blocked: true,
    },
  });
}

/**
 * Convenience function to log a search execution.
 */
export function auditSearchExecuted(
  query: string,
  result: {
    searchId: string;
    eventCount: number;
    executionTimeMs: number;
    trustScore?: number;
  }
): void {
  logAuditEvent({
    type: AuditEventType.SEARCH_EXECUTED,
    query,
    result: {
      success: true,
      eventCount: result.eventCount,
      executionTimeMs: result.executionTimeMs,
      trustScore: result.trustScore,
    },
  });
}

/**
 * Sanitize a query for logging (remove potential secrets).
 */
function sanitizeQuery(query: string): string {
  // Truncate long queries
  let sanitized = query.length > 500 ? query.substring(0, 500) + '...' : query;

  // Remove potential secrets
  sanitized = sanitized.replace(/password\s*=\s*["'][^"']*["']/gi, 'password="***"');
  sanitized = sanitized.replace(/token\s*=\s*["'][^"']*["']/gi, 'token="***"');
  sanitized = sanitized.replace(/api_key\s*=\s*["'][^"']*["']/gi, 'api_key="***"');

  return sanitized;
}

/**
 * Sanitize parameters for logging.
 */
function sanitizeParameters(params: Record<string, unknown>): Record<string, unknown> {
  const sensitiveFields = ['password', 'token', 'api_key', 'secret', 'credential'];
  const sanitized: Record<string, unknown> = {};

  for (const [key, value] of Object.entries(params)) {
    if (sensitiveFields.some((f) => key.toLowerCase().includes(f))) {
      sanitized[key] = '***';
    } else if (typeof value === 'string' && value.length > 200) {
      sanitized[key] = value.substring(0, 200) + '...';
    } else {
      sanitized[key] = value;
    }
  }

  return sanitized;
}

/**
 * Audit logger class for use with the MCP server.
 */
export class AuditLogger {
  private enabled: boolean;

  constructor(enabled = true) {
    this.enabled = enabled && settings.enableAuditLog;
  }

  logToolCall(toolName: string, parameters: Record<string, unknown>): void {
    if (this.enabled) {
      auditToolCall(toolName, parameters);
    }
  }

  logToolSuccess(
    toolName: string,
    result: { eventCount?: number; executionTimeMs?: number; trustScore?: number }
  ): void {
    if (this.enabled) {
      auditToolSuccess(toolName, result);
    }
  }

  logToolError(toolName: string, error: Error, isSecurityError = false): void {
    if (this.enabled) {
      auditToolError(toolName, error, isSecurityError);
    }
  }

  logSecurityViolation(
    toolName: string,
    query: string,
    riskLevel: string,
    issues: string[]
  ): void {
    if (this.enabled) {
      auditSecurityViolation(toolName, query, riskLevel, issues);
    }
  }

  async flush(): Promise<void> {
    flushAuditLog();
  }
}
