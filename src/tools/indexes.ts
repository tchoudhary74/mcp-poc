/** splunk_list_indexes tool - List available Splunk indexes */

import { SplunkClient } from '../splunk/client.js';
import { isValidIdentifier } from '../security/validators.js';
import { ListIndexesInputSchema, ValidationError } from '../types.js';
import { createChildLogger } from '../logging/logger.js';

const logger = createChildLogger('tool-indexes');

/** Tool definition for MCP */
export const listIndexesToolDefinition = {
  name: 'splunk_list_indexes',
  description: `List available Splunk indexes that can be queried.

Use this tool to discover what indexes are available before running searches.

Parameters:
- filter: Optional filter to match index names (partial match)

Returns a list of indexes with their metadata including event counts and sizes.`,
  inputSchema: {
    type: 'object' as const,
    properties: {
      filter: {
        type: 'string',
        description: 'Filter index names (partial match)',
      },
    },
    required: [],
  },
};

/** Execute the list_indexes tool */
export async function executeListIndexes(
  client: SplunkClient,
  params: unknown
): Promise<{ indexes: unknown[]; metadata: unknown }> {
  // Validate input
  const parseResult = ListIndexesInputSchema.safeParse(params);
  if (!parseResult.success) {
    throw new ValidationError(`Invalid input: ${parseResult.error.message}`);
  }

  const { filter } = parseResult.data;

  // Validate filter if provided
  if (filter && !isValidIdentifier(filter) && !/^[a-zA-Z0-9_\-\.\*]+$/.test(filter)) {
    throw new ValidationError(`Invalid filter: ${filter}`);
  }

  logger.info('Listing indexes', { filter });

  const indexes = await client.listIndexes(filter);

  return {
    indexes: indexes.map((idx) => ({
      name: idx.name,
      totalEventCount: parseInt(idx.totalEventCount, 10) || 0,
      currentDBSizeMB: parseFloat(idx.currentDBSizeMB) || 0,
      maxDataSizeMB: parseFloat(idx.maxDataSizeMB) || 0,
      retentionDays: Math.round(parseInt(idx.frozenTimePeriodInSecs, 10) / 86400) || 0,
    })),
    metadata: {
      count: indexes.length,
      filter: filter || null,
    },
  };
}
