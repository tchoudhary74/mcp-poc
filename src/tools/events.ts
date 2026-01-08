/** splunk_get_events tool - Retrieve events from a specific index */

import { SplunkClient } from '../splunk/client.js';
import { assertQuerySafe } from '../security/scanner.js';
import {
  isValidIdentifier,
  isValidTimeSpec,
  isValidHostname,
  isValidSourcePath,
  escapeSPLString,
} from '../security/validators.js';
import { GetEventsInputSchema, ValidationError } from '../types.js';
import { createChildLogger } from '../logging/logger.js';

const logger = createChildLogger('tool-events');

/** Tool definition for MCP */
export const getEventsToolDefinition = {
  name: 'splunk_get_events',
  description: `Retrieve events from a specific Splunk index with optional filtering.

Use this tool to fetch raw events from an index, optionally filtered by source, sourcetype, or host.

Parameters:
- index: Name of the index to query (required)
- earliest_time: Start time (default: -24h)
- latest_time: End time (default: now)
- max_results: Maximum events to return (default: 100)
- source: Filter by source path (optional)
- sourcetype: Filter by sourcetype (optional)
- host: Filter by hostname (optional)

Example:
- index=main, sourcetype=syslog - Get syslog events from main index
- index=security, host=firewall01 - Get events from a specific host`,
  inputSchema: {
    type: 'object' as const,
    properties: {
      index: {
        type: 'string',
        description: 'Index name to query',
      },
      earliest_time: {
        type: 'string',
        description: 'Start time',
        default: '-24h',
      },
      latest_time: {
        type: 'string',
        description: 'End time',
        default: 'now',
      },
      max_results: {
        type: 'number',
        description: 'Maximum events to return',
        default: 100,
      },
      source: {
        type: 'string',
        description: 'Filter by source path',
      },
      sourcetype: {
        type: 'string',
        description: 'Filter by sourcetype',
      },
      host: {
        type: 'string',
        description: 'Filter by hostname',
      },
    },
    required: ['index'],
  },
};

/** Execute the get_events tool */
export async function executeGetEvents(
  client: SplunkClient,
  params: unknown
): Promise<{ events: unknown[]; metadata: unknown }> {
  // Validate input
  const parseResult = GetEventsInputSchema.safeParse(params);
  if (!parseResult.success) {
    throw new ValidationError(`Invalid input: ${parseResult.error.message}`);
  }

  const { index, earliest_time, latest_time, max_results, source, sourcetype, host } =
    parseResult.data;

  // Validate index
  if (!isValidIdentifier(index)) {
    throw new ValidationError(`Invalid index name: ${index}`);
  }

  // Validate time specs
  if (!isValidTimeSpec(earliest_time)) {
    throw new ValidationError(`Invalid earliest_time: ${earliest_time}`);
  }
  if (!isValidTimeSpec(latest_time)) {
    throw new ValidationError(`Invalid latest_time: ${latest_time}`);
  }

  // Validate optional filters
  if (sourcetype && !isValidIdentifier(sourcetype)) {
    throw new ValidationError(`Invalid sourcetype: ${sourcetype}`);
  }
  if (host && !isValidHostname(host)) {
    throw new ValidationError(`Invalid hostname: ${host}`);
  }
  if (source && !isValidSourcePath(source)) {
    throw new ValidationError(`Invalid source path: ${source}`);
  }

  // Build query
  const queryParts: string[] = [`index=${index}`];

  if (sourcetype) {
    queryParts.push(`sourcetype="${escapeSPLString(sourcetype)}"`);
  }
  if (host) {
    queryParts.push(`host="${escapeSPLString(host)}"`);
  }
  if (source) {
    queryParts.push(`source="${escapeSPLString(source)}"`);
  }

  const query = queryParts.join(' ');

  // Security scan
  assertQuerySafe(query);

  logger.info('Getting events', {
    index,
    filters: { sourcetype, host, source },
    earliest_time,
    latest_time,
    max_results,
  });

  // Execute search
  const result = await client.search(query, {
    earliestTime: earliest_time,
    latestTime: latest_time,
    maxResults: max_results,
  });

  return {
    events: result.events,
    metadata: {
      index,
      searchId: result.searchId,
      totalCount: result.totalCount,
      returnedCount: result.events.length,
      truncated: result.truncated,
      executionTimeMs: result.executionTimeMs,
    },
  };
}
