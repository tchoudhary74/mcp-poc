/** splunk_correlate tool - Find related events based on correlation fields */

import { SplunkClient } from '../splunk/client.js';
import { assertQuerySafe } from '../security/scanner.js';
import { isValidEventId, isValidTimeSpec, isValidFieldName, escapeSPLString } from '../security/validators.js';
import { CorrelateInputSchema, ValidationError } from '../types.js';
import { createChildLogger } from '../logging/logger.js';

const logger = createChildLogger('tool-correlate');

/** Tool definition for MCP */
export const correlateToolDefinition = {
  name: 'splunk_correlate',
  description: `Find events that are related to a specific event based on correlation fields.

Use this tool to investigate incidents by finding related events that share common attributes
like host, user, source IP, or other fields.

Parameters:
- event_id: The _cd or unique identifier of the source event (required)
- time_window: Time window around the event to search (default: 5m)
- correlation_fields: Fields to use for correlation (default: ['host', 'source', 'user'])
- max_results: Maximum related events to return (default: 100)

Example:
- Correlate by event_id with fields ['host', 'src_ip', 'user'] to find related network activity

Returns events that share values with the source event in the specified fields.`,
  inputSchema: {
    type: 'object' as const,
    properties: {
      event_id: {
        type: 'string',
        description: 'Unique identifier of the source event',
      },
      time_window: {
        type: 'string',
        description: 'Time window to search (e.g., 5m, 1h)',
        default: '5m',
      },
      correlation_fields: {
        type: 'array',
        items: { type: 'string' },
        description: 'Fields to correlate on',
        default: ['host', 'source', 'user'],
      },
      max_results: {
        type: 'number',
        description: 'Maximum related events to return',
        default: 100,
      },
    },
    required: ['event_id'],
  },
};

/** Execute the correlate tool */
export async function executeCorrelate(
  client: SplunkClient,
  params: unknown
): Promise<{ sourceEvent: unknown; relatedEvents: unknown[]; metadata: unknown }> {
  // Validate input
  const parseResult = CorrelateInputSchema.safeParse(params);
  if (!parseResult.success) {
    throw new ValidationError(`Invalid input: ${parseResult.error.message}`);
  }

  const { event_id, time_window, correlation_fields, max_results } = parseResult.data;

  // Validate event_id
  if (!isValidEventId(event_id)) {
    throw new ValidationError(`Invalid event_id: ${event_id}`);
  }

  // Validate time_window
  if (!isValidTimeSpec(`-${time_window}`.replace('--', '-'))) {
    throw new ValidationError(`Invalid time_window: ${time_window}`);
  }

  // Validate correlation fields
  for (const field of correlation_fields) {
    if (!isValidFieldName(field)) {
      throw new ValidationError(`Invalid correlation field: ${field}`);
    }
  }

  logger.info('Correlating events', {
    event_id,
    time_window,
    correlation_fields,
    max_results,
  });

  // First, find the source event
  const sourceQuery = `_cd="${escapeSPLString(event_id)}" OR _serial="${escapeSPLString(event_id)}"`;
  assertQuerySafe(sourceQuery);

  const sourceResult = await client.search(sourceQuery, {
    maxResults: 1,
  });

  if (sourceResult.events.length === 0) {
    return {
      sourceEvent: null,
      relatedEvents: [],
      metadata: {
        event_id,
        error: 'Source event not found',
      },
    };
  }

  const sourceEvent = sourceResult.events[0];

  // Build correlation query based on source event fields
  const correlationClauses: string[] = [];

  for (const field of correlation_fields) {
    const fieldValue = sourceEvent.fields[field] || (sourceEvent as Record<string, unknown>)[field];
    if (fieldValue && typeof fieldValue === 'string' && fieldValue.trim()) {
      correlationClauses.push(`${field}="${escapeSPLString(fieldValue)}"`);
    }
  }

  if (correlationClauses.length === 0) {
    return {
      sourceEvent,
      relatedEvents: [],
      metadata: {
        event_id,
        error: 'No correlation fields found in source event',
        correlation_fields,
      },
    };
  }

  // Search for related events
  const correlationQuery = `(${correlationClauses.join(' OR ')}) NOT (_cd="${escapeSPLString(event_id)}")`;
  assertQuerySafe(correlationQuery);

  // Parse time window for relative search
  const timeWindowMatch = time_window.match(/^(\d+)([smhd])$/);
  let earliestTime = '-5m';
  let latestTime = '+5m';

  if (timeWindowMatch) {
    earliestTime = `-${time_window}`;
    latestTime = `+${time_window}`;
  }

  const relatedResult = await client.search(correlationQuery, {
    earliestTime,
    latestTime,
    maxResults: max_results,
  });

  return {
    sourceEvent,
    relatedEvents: relatedResult.events,
    metadata: {
      event_id,
      correlation_fields,
      correlationClauses,
      timeWindow: time_window,
      totalRelated: relatedResult.totalCount,
      returnedRelated: relatedResult.events.length,
      truncated: relatedResult.truncated,
      searchId: relatedResult.searchId,
      executionTimeMs: relatedResult.executionTimeMs,
    },
  };
}
