/** splunk_get_context tool - Get events before and after a specific event */

import { SplunkClient } from '../splunk/client.js';
import { assertQuerySafe } from '../security/scanner.js';
import { isValidEventId, escapeSPLString } from '../security/validators.js';
import { GetContextInputSchema, ValidationError } from '../types.js';
import { createChildLogger } from '../logging/logger.js';

const logger = createChildLogger('tool-context');

/** Tool definition for MCP */
export const getContextToolDefinition = {
  name: 'splunk_get_context',
  description: `Get events that occurred before and after a specific event.

Use this tool to understand what happened around a particular event, useful for
incident investigation and root cause analysis.

Parameters:
- event_id: The _cd or unique identifier of the target event (required)
- before_count: Number of events to retrieve before the target (default: 10)
- after_count: Number of events to retrieve after the target (default: 10)

Returns the target event along with surrounding events from the same source.`,
  inputSchema: {
    type: 'object' as const,
    properties: {
      event_id: {
        type: 'string',
        description: 'Unique identifier of the target event',
      },
      before_count: {
        type: 'number',
        description: 'Number of events before',
        default: 10,
      },
      after_count: {
        type: 'number',
        description: 'Number of events after',
        default: 10,
      },
    },
    required: ['event_id'],
  },
};

/** Execute the get_context tool */
export async function executeGetContext(
  client: SplunkClient,
  params: unknown
): Promise<{
  beforeEvents: unknown[];
  targetEvent: unknown;
  afterEvents: unknown[];
  metadata: unknown;
}> {
  // Validate input
  const parseResult = GetContextInputSchema.safeParse(params);
  if (!parseResult.success) {
    throw new ValidationError(`Invalid input: ${parseResult.error.message}`);
  }

  const { event_id, before_count, after_count } = parseResult.data;

  // Validate event_id
  if (!isValidEventId(event_id)) {
    throw new ValidationError(`Invalid event_id: ${event_id}`);
  }

  logger.info('Getting event context', {
    event_id,
    before_count,
    after_count,
  });

  // First, find the target event to get its timestamp and source
  const targetQuery = `_cd="${escapeSPLString(event_id)}" OR _serial="${escapeSPLString(event_id)}"`;
  assertQuerySafe(targetQuery);

  const targetResult = await client.search(targetQuery, {
    maxResults: 1,
  });

  if (targetResult.events.length === 0) {
    return {
      beforeEvents: [],
      targetEvent: null,
      afterEvents: [],
      metadata: {
        event_id,
        error: 'Target event not found',
      },
    };
  }

  const targetEvent = targetResult.events[0];
  const targetTime = targetEvent._time;
  const targetIndex = targetEvent.index || '*';
  const targetHost = targetEvent.host;
  const targetSource = targetEvent.source;

  // Build context queries
  const contextFilters: string[] = [];
  if (targetHost) contextFilters.push(`host="${escapeSPLString(targetHost)}"`);
  if (targetSource) contextFilters.push(`source="${escapeSPLString(targetSource)}"`);

  const contextBase = contextFilters.length > 0 ? contextFilters.join(' ') : '*';

  // Get events before
  const beforeQuery = `index=${targetIndex} ${contextBase} _time<"${targetTime}" | head ${before_count} | reverse`;
  assertQuerySafe(beforeQuery);

  const beforeResult = await client.search(beforeQuery, {
    maxResults: before_count,
  });

  // Get events after
  const afterQuery = `index=${targetIndex} ${contextBase} _time>"${targetTime}" | head ${after_count}`;
  assertQuerySafe(afterQuery);

  const afterResult = await client.search(afterQuery, {
    maxResults: after_count,
  });

  return {
    beforeEvents: beforeResult.events,
    targetEvent,
    afterEvents: afterResult.events,
    metadata: {
      event_id,
      targetTime,
      targetHost,
      targetSource,
      beforeCount: beforeResult.events.length,
      afterCount: afterResult.events.length,
      totalExecutionTimeMs:
        targetResult.executionTimeMs +
        beforeResult.executionTimeMs +
        afterResult.executionTimeMs,
    },
  };
}
