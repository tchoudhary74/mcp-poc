/** splunk_list_alerts tool - List fired alerts from Splunk */

import { SplunkClient } from '../splunk/client.js';
import { isValidTimeSpec } from '../security/validators.js';
import { ListAlertsInputSchema, ValidationError } from '../types.js';
import { createChildLogger } from '../logging/logger.js';

const logger = createChildLogger('tool-alerts');

/** Tool definition for MCP */
export const listAlertsToolDefinition = {
  name: 'splunk_list_alerts',
  description: `List triggered alerts from Splunk.

Use this tool to see what alerts have fired recently, useful for SOC triage
and incident response.

Parameters:
- severity: Filter by severity level (info, low, medium, high, critical)
- earliest_time: Only show alerts triggered after this time (default: -24h)

Returns a list of fired alerts with their severity, trigger time, and message.`,
  inputSchema: {
    type: 'object' as const,
    properties: {
      severity: {
        type: 'string',
        enum: ['info', 'low', 'medium', 'high', 'critical'],
        description: 'Filter by severity level',
      },
      earliest_time: {
        type: 'string',
        description: 'Only show alerts after this time',
        default: '-24h',
      },
    },
    required: [],
  },
};

/** Execute the list_alerts tool */
export async function executeListAlerts(
  client: SplunkClient,
  params: unknown
): Promise<{ alerts: unknown[]; metadata: unknown }> {
  // Validate input
  const parseResult = ListAlertsInputSchema.safeParse(params);
  if (!parseResult.success) {
    throw new ValidationError(`Invalid input: ${parseResult.error.message}`);
  }

  const { severity, earliest_time } = parseResult.data;

  // Validate earliest_time
  if (!isValidTimeSpec(earliest_time)) {
    throw new ValidationError(`Invalid earliest_time: ${earliest_time}`);
  }

  logger.info('Listing alerts', { severity, earliest_time });

  const alerts = await client.listFiredAlerts(severity, earliest_time);

  // Group by severity for summary
  const severityCounts: Record<string, number> = {};
  for (const alert of alerts) {
    const sev = alert.severity.toLowerCase();
    severityCounts[sev] = (severityCounts[sev] || 0) + 1;
  }

  return {
    alerts: alerts.map((alert) => ({
      name: alert.name,
      severity: alert.severity,
      triggeredTime: alert.triggeredTime,
      message: alert.message,
      app: alert.app,
      resultCount: alert.resultCount,
    })),
    metadata: {
      count: alerts.length,
      severityFilter: severity || 'all',
      earliestTime: earliest_time,
      severityCounts,
    },
  };
}
