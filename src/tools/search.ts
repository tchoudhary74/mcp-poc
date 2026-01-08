/** splunk_search tool - Execute SPL queries against Splunk */

import { SplunkClient } from '../splunk/client.js';
import { assertQuerySafe } from '../security/scanner.js';
import { isValidIdentifier, isValidTimeSpec } from '../security/validators.js';
import { SearchInputSchema, ValidationError } from '../types.js';
import { createChildLogger } from '../logging/logger.js';

const logger = createChildLogger('tool-search');

/** Tool definition for MCP */
export const searchToolDefinition = {
  name: 'splunk_search',
  description: `Execute a Splunk SPL query and return results with trust metadata.

Use this tool to run ad-hoc searches against Splunk indexes.

Parameters:
- query: SPL query string (required). Can be a full SPL query or just search terms.
- earliest_time: Start time for the search (default: -24h). Supports relative time (-24h, -7d) or absolute time.
- latest_time: End time for the search (default: now).
- max_results: Maximum number of events to return (default: 1000, max: 10000).
- index: Optional index to search. If not specified, searches default indexes.

Example queries:
- "index=main error" - Search for errors in main index
- "sourcetype=access_combined status>=400" - Find HTTP errors
- "index=security failed login | stats count by user" - Count failed logins

Returns events with trust scoring to indicate data quality and reliability.`,
  inputSchema: {
    type: 'object' as const,
    properties: {
      query: {
        type: 'string',
        description: 'SPL query to execute',
      },
      earliest_time: {
        type: 'string',
        description: 'Start time (e.g., -24h, -7d, 2024-01-01T00:00:00)',
        default: '-24h',
      },
      latest_time: {
        type: 'string',
        description: 'End time (e.g., now, -1h, 2024-01-02T00:00:00)',
        default: 'now',
      },
      max_results: {
        type: 'number',
        description: 'Maximum events to return (1-10000)',
        default: 1000,
      },
      index: {
        type: 'string',
        description: 'Specific index to search (optional)',
      },
    },
    required: ['query'],
  },
};

/** Execute the search tool */
export async function executeSearch(
  client: SplunkClient,
  params: unknown
): Promise<{ events: unknown[]; metadata: unknown }> {
  // Validate input
  const parseResult = SearchInputSchema.safeParse(params);
  if (!parseResult.success) {
    throw new ValidationError(`Invalid input: ${parseResult.error.message}`);
  }

  const { query, earliest_time, latest_time, max_results, index } = parseResult.data;

  // Validate time specifications
  if (!isValidTimeSpec(earliest_time)) {
    throw new ValidationError(`Invalid earliest_time: ${earliest_time}`);
  }
  if (!isValidTimeSpec(latest_time)) {
    throw new ValidationError(`Invalid latest_time: ${latest_time}`);
  }

  // Validate index if provided
  if (index && !isValidIdentifier(index)) {
    throw new ValidationError(`Invalid index name: ${index}`);
  }

  // Build the full query
  let fullQuery = query;
  if (index && !query.toLowerCase().includes('index=')) {
    fullQuery = `index=${index} ${query}`;
  }

  // Security scan
  assertQuerySafe(fullQuery);

  logger.info('Executing search', {
    query: fullQuery.substring(0, 100),
    earliest_time,
    latest_time,
    max_results,
  });

  // Execute search
  const result = await client.search(fullQuery, {
    earliestTime: earliest_time,
    latestTime: latest_time,
    maxResults: max_results,
  });

  return {
    events: result.events,
    metadata: {
      searchId: result.searchId,
      totalCount: result.totalCount,
      returnedCount: result.events.length,
      truncated: result.truncated,
      executionTimeMs: result.executionTimeMs,
    },
  };
}
