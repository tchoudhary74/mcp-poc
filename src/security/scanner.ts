/** Security scanner for detecting injection attacks and read-only violations */

import { createChildLogger } from '../logging/logger.js';
import { InjectionError, ReadOnlyViolationError, SecurityError } from '../types.js';

const logger = createChildLogger('security-scanner');

/** Scan result with details */
export interface ScanResult {
  safe: boolean;
  risk: 'none' | 'low' | 'medium' | 'high' | 'critical';
  issues: SecurityIssue[];
}

export interface SecurityIssue {
  type: 'injection' | 'read_only_violation' | 'prompt_injection' | 'data_exfiltration';
  severity: 'low' | 'medium' | 'high' | 'critical';
  description: string;
  pattern: string;
}

/** Read-only violation patterns - commands that modify data */
const READ_ONLY_VIOLATIONS: Array<{ pattern: RegExp; description: string }> = [
  { pattern: /\|\s*delete\b/i, description: 'DELETE command detected' },
  { pattern: /\|\s*collect\b/i, description: 'COLLECT command detected (writes to index)' },
  { pattern: /\|\s*outputcsv\b/i, description: 'OUTPUTCSV command detected' },
  { pattern: /\|\s*outputlookup\b/i, description: 'OUTPUTLOOKUP command detected' },
  { pattern: /\|\s*sendemail\b/i, description: 'SENDEMAIL command detected' },
  { pattern: /\|\s*sendalert\b/i, description: 'SENDALERT command detected' },
  { pattern: /\|\s*script\b/i, description: 'SCRIPT command detected' },
  { pattern: /\|\s*run\b/i, description: 'RUN command detected' },
  { pattern: /\|\s*runshellscript\b/i, description: 'RUNSHELLSCRIPT command detected' },
  { pattern: /\|\s*mcollect\b/i, description: 'MCOLLECT command detected' },
  { pattern: /\|\s*meventcollect\b/i, description: 'MEVENTCOLLECT command detected' },
];

/** SPL injection patterns */
const SPL_INJECTION_PATTERNS: Array<{ pattern: RegExp; description: string; severity: 'medium' | 'high' | 'critical' }> = [
  // Command injection via pipe
  { pattern: /\|\s*eval\s+.*\bexec\s*\(/i, severity: 'critical', description: 'Command execution via eval' },
  { pattern: /\|\s*python\b/i, severity: 'critical', description: 'Python script execution' },
  { pattern: /\|\s*ruby\b/i, severity: 'critical', description: 'Ruby script execution' },
  { pattern: /\|\s*perl\b/i, severity: 'critical', description: 'Perl script execution' },

  // REST API abuse
  { pattern: /\|\s*rest\s+\/services\/server\/control/i, severity: 'critical', description: 'Server control API access' },
  { pattern: /\|\s*rest\s+\/services\/admin/i, severity: 'high', description: 'Admin API access' },
  { pattern: /\|\s*rest\s+.*\bpassword\b/i, severity: 'high', description: 'Password-related API access' },

  // File system access
  { pattern: /\|\s*inputcsv\s+[^|]*\.\./i, severity: 'high', description: 'Path traversal in inputcsv' },
  { pattern: /\|\s*inputlookup\s+[^|]*\.\./i, severity: 'high', description: 'Path traversal in inputlookup' },

  // Comment-based injection
  { pattern: /```[\s\S]*?\|/i, severity: 'medium', description: 'Markdown code block with pipe' },

  // Subsearch injection
  { pattern: /\[\s*\|\s*makeresults/i, severity: 'medium', description: 'Suspicious subsearch with makeresults' },
];

/** Prompt injection patterns */
const PROMPT_INJECTION_PATTERNS: Array<{ pattern: RegExp; description: string }> = [
  { pattern: /(ignore|override|skip|disable).*(previous|above|instruction|directive)/i, description: 'Instruction override attempt' },
  { pattern: /(forget|disregard).*(rule|constraint|limitation)/i, description: 'Rule bypass attempt' },
  { pattern: /pretend\s+(you\s+are|to\s+be)/i, description: 'Identity manipulation' },
  { pattern: /you\s+are\s+now\s+(a|an)/i, description: 'Role reassignment' },
  { pattern: /act\s+as\s+(if|though)/i, description: 'Behavior modification' },
  { pattern: /system\s*:\s*you\s+are/i, description: 'Fake system prompt' },
  { pattern: /<\/?system>/i, description: 'System tag injection' },
  { pattern: /\[INST\]/i, description: 'Instruction format injection' },
  { pattern: /###\s*(system|instruction|human|assistant)/i, description: 'Format injection' },
  { pattern: /new\s+instructions?\s*:/i, description: 'New instructions injection' },
];

/** Data exfiltration patterns */
const DATA_EXFILTRATION_PATTERNS: Array<{ pattern: RegExp; description: string }> = [
  { pattern: /\|\s*curl\b/i, description: 'HTTP request via curl' },
  { pattern: /\|\s*wget\b/i, description: 'HTTP request via wget' },
  { pattern: /https?:\/\/[^\s"'\]]+/i, description: 'External URL reference' },
  { pattern: /\|\s*rest\s+https?:\/\//i, description: 'External REST call' },
];

/**
 * Scan a query for security issues.
 */
export function scanQuery(query: string): ScanResult {
  const issues: SecurityIssue[] = [];

  // Check read-only violations
  for (const { pattern, description } of READ_ONLY_VIOLATIONS) {
    if (pattern.test(query)) {
      issues.push({
        type: 'read_only_violation',
        severity: 'critical',
        description,
        pattern: pattern.source,
      });
    }
  }

  // Check SPL injection patterns
  for (const { pattern, description, severity } of SPL_INJECTION_PATTERNS) {
    if (pattern.test(query)) {
      issues.push({
        type: 'injection',
        severity,
        description,
        pattern: pattern.source,
      });
    }
  }

  // Check prompt injection patterns
  for (const { pattern, description } of PROMPT_INJECTION_PATTERNS) {
    if (pattern.test(query)) {
      issues.push({
        type: 'prompt_injection',
        severity: 'high',
        description,
        pattern: pattern.source,
      });
    }
  }

  // Check data exfiltration patterns
  for (const { pattern, description } of DATA_EXFILTRATION_PATTERNS) {
    if (pattern.test(query)) {
      issues.push({
        type: 'data_exfiltration',
        severity: 'medium',
        description,
        pattern: pattern.source,
      });
    }
  }

  // Determine overall risk level
  const risk = determineRiskLevel(issues);

  logger.debug('Query scanned', {
    issueCount: issues.length,
    risk,
    safe: issues.length === 0,
  });

  return {
    safe: issues.length === 0,
    risk,
    issues,
  };
}

/**
 * Scan a query and throw an error if unsafe.
 */
export function assertQuerySafe(query: string): void {
  const result = scanQuery(query);

  if (!result.safe) {
    const criticalIssues = result.issues.filter((i) => i.severity === 'critical');
    const readOnlyViolations = result.issues.filter((i) => i.type === 'read_only_violation');

    // Log the security event
    logger.warn('Security scan failed', {
      query: query.substring(0, 200),
      risk: result.risk,
      issues: result.issues.map((i) => ({ type: i.type, description: i.description })),
    });

    // Throw appropriate error type
    if (readOnlyViolations.length > 0) {
      throw new ReadOnlyViolationError(
        `Query contains read-only violations: ${readOnlyViolations.map((i) => i.description).join(', ')}`
      );
    }

    if (criticalIssues.length > 0) {
      throw new InjectionError(
        `Query contains critical security issues: ${criticalIssues.map((i) => i.description).join(', ')}`
      );
    }

    throw new SecurityError(
      `Query failed security scan (${result.risk} risk): ${result.issues.map((i) => i.description).join(', ')}`
    );
  }
}

/**
 * Determine overall risk level from issues.
 */
function determineRiskLevel(issues: SecurityIssue[]): 'none' | 'low' | 'medium' | 'high' | 'critical' {
  if (issues.length === 0) return 'none';

  const hasCritical = issues.some((i) => i.severity === 'critical');
  if (hasCritical) return 'critical';

  const hasHigh = issues.some((i) => i.severity === 'high');
  if (hasHigh) return 'high';

  const hasMedium = issues.some((i) => i.severity === 'medium');
  if (hasMedium) return 'medium';

  return 'low';
}

/**
 * Scan input parameters for injection attempts.
 */
export function scanParameters(params: Record<string, unknown>): ScanResult {
  const issues: SecurityIssue[] = [];

  for (const [key, value] of Object.entries(params)) {
    if (typeof value === 'string') {
      const stringResult = scanQuery(value);
      issues.push(
        ...stringResult.issues.map((i) => ({
          ...i,
          description: `[${key}] ${i.description}`,
        }))
      );
    } else if (Array.isArray(value)) {
      for (const item of value) {
        if (typeof item === 'string') {
          const arrayResult = scanQuery(item);
          issues.push(
            ...arrayResult.issues.map((i) => ({
              ...i,
              description: `[${key}[]] ${i.description}`,
            }))
          );
        }
      }
    }
  }

  return {
    safe: issues.length === 0,
    risk: determineRiskLevel(issues),
    issues,
  };
}
