/** splunk_list_saved_searches and splunk_run_saved_search tools */

import { SplunkClient } from '../splunk/client.js';
import { isValidIdentifier } from '../security/validators.js';
import {
  ListSavedSearchesInputSchema,
  RunSavedSearchInputSchema,
  ValidationError,
} from '../types.js';
import { createChildLogger } from '../logging/logger.js';

const logger = createChildLogger('tool-saved-searches');

/** Tool definition for list_saved_searches */
export const listSavedSearchesToolDefinition = {
  name: 'splunk_list_saved_searches',
  description: `List saved searches (reports) available in Splunk.

Use this tool to discover pre-built searches that can be executed.

Parameters:
- app: Filter by Splunk app (optional)
- owner: Filter by owner (optional)

Returns a list of saved searches with their names, descriptions, and schedules.`,
  inputSchema: {
    type: 'object' as const,
    properties: {
      app: {
        type: 'string',
        description: 'Filter by Splunk app',
      },
      owner: {
        type: 'string',
        description: 'Filter by owner',
      },
    },
    required: [],
  },
};

/** Tool definition for run_saved_search */
export const runSavedSearchToolDefinition = {
  name: 'splunk_run_saved_search',
  description: `Execute a saved search (report) and return the results.

Use this tool to run a pre-built saved search by name.

Parameters:
- name: Name of the saved search to run (required)
- earliest_time: Override start time (optional)
- latest_time: Override end time (optional)

Returns the search results with metadata.`,
  inputSchema: {
    type: 'object' as const,
    properties: {
      name: {
        type: 'string',
        description: 'Name of the saved search',
      },
      earliest_time: {
        type: 'string',
        description: 'Override start time',
      },
      latest_time: {
        type: 'string',
        description: 'Override end time',
      },
    },
    required: ['name'],
  },
};

/** Execute the list_saved_searches tool */
export async function executeListSavedSearches(
  client: SplunkClient,
  params: unknown
): Promise<{ savedSearches: unknown[]; metadata: unknown }> {
  // Validate input
  const parseResult = ListSavedSearchesInputSchema.safeParse(params);
  if (!parseResult.success) {
    throw new ValidationError(`Invalid input: ${parseResult.error.message}`);
  }

  const { app, owner } = parseResult.data;

  // Validate app and owner if provided
  if (app && !isValidIdentifier(app)) {
    throw new ValidationError(`Invalid app: ${app}`);
  }
  if (owner && !isValidIdentifier(owner)) {
    throw new ValidationError(`Invalid owner: ${owner}`);
  }

  logger.info('Listing saved searches', { app, owner });

  const savedSearches = await client.listSavedSearches(app, owner);

  return {
    savedSearches: savedSearches.map((ss) => ({
      name: ss.name,
      description: ss.description,
      app: ss.app,
      owner: ss.owner,
      isScheduled: ss.isScheduled,
      cronSchedule: ss.cronSchedule || null,
      searchPreview:
        ss.search.length > 100 ? ss.search.substring(0, 100) + '...' : ss.search,
    })),
    metadata: {
      count: savedSearches.length,
      app: app || 'all',
      owner: owner || 'all',
    },
  };
}

/** Execute the run_saved_search tool */
export async function executeRunSavedSearch(
  client: SplunkClient,
  params: unknown
): Promise<{ events: unknown[]; metadata: unknown }> {
  // Validate input
  const parseResult = RunSavedSearchInputSchema.safeParse(params);
  if (!parseResult.success) {
    throw new ValidationError(`Invalid input: ${parseResult.error.message}`);
  }

  const { name, earliest_time, latest_time } = parseResult.data;

  // Validate name (saved search names can have spaces and special chars)
  if (!name || name.length > 256) {
    throw new ValidationError(`Invalid saved search name: ${name}`);
  }

  logger.info('Running saved search', { name, earliest_time, latest_time });

  const result = await client.runSavedSearch(name, earliest_time, latest_time);

  return {
    events: result.events,
    metadata: {
      savedSearchName: name,
      searchId: result.searchId,
      totalCount: result.totalCount,
      returnedCount: result.events.length,
      truncated: result.truncated,
      executionTimeMs: result.executionTimeMs,
      timeOverrides: {
        earliest: earliest_time || 'default',
        latest: latest_time || 'default',
      },
    },
  };
}
