/** Tool exports and registry for MCP */

import { SplunkClient } from '../splunk/client.js';
import { createChildLogger } from '../logging/logger.js';

// Import tool definitions and executors
import { searchToolDefinition, executeSearch } from './search.js';
import { getEventsToolDefinition, executeGetEvents } from './events.js';
import { correlateToolDefinition, executeCorrelate } from './correlate.js';
import { getContextToolDefinition, executeGetContext } from './context.js';
import { listIndexesToolDefinition, executeListIndexes } from './indexes.js';
import {
  listSavedSearchesToolDefinition,
  runSavedSearchToolDefinition,
  executeListSavedSearches,
  executeRunSavedSearch,
} from './saved-searches.js';
import { listAlertsToolDefinition, executeListAlerts } from './alerts.js';

const logger = createChildLogger('tools');

/** All tool definitions for MCP registration */
export const toolDefinitions = [
  searchToolDefinition,
  getEventsToolDefinition,
  correlateToolDefinition,
  getContextToolDefinition,
  listIndexesToolDefinition,
  listSavedSearchesToolDefinition,
  runSavedSearchToolDefinition,
  listAlertsToolDefinition,
];

/** Tool executor type */
type ToolExecutor = (client: SplunkClient, params: unknown) => Promise<unknown>;

/** Map of tool names to their executors */
const toolExecutors: Record<string, ToolExecutor> = {
  splunk_search: executeSearch,
  splunk_get_events: executeGetEvents,
  splunk_correlate: executeCorrelate,
  splunk_get_context: executeGetContext,
  splunk_list_indexes: executeListIndexes,
  splunk_list_saved_searches: executeListSavedSearches,
  splunk_run_saved_search: executeRunSavedSearch,
  splunk_list_alerts: executeListAlerts,
};

/**
 * Execute a tool by name with the given parameters.
 */
export async function executeTool(
  toolName: string,
  params: unknown,
  client: SplunkClient
): Promise<unknown> {
  const executor = toolExecutors[toolName];

  if (!executor) {
    throw new Error(`Unknown tool: ${toolName}`);
  }

  logger.debug('Executing tool', { toolName });

  const startTime = Date.now();
  try {
    const result = await executor(client, params);
    const executionTime = Date.now() - startTime;

    logger.info('Tool executed successfully', {
      toolName,
      executionTimeMs: executionTime,
    });

    return result;
  } catch (error) {
    const executionTime = Date.now() - startTime;

    logger.error('Tool execution failed', {
      toolName,
      executionTimeMs: executionTime,
      error: error instanceof Error ? error.message : String(error),
    });

    throw error;
  }
}

/** Get the list of available tool names */
export function getToolNames(): string[] {
  return Object.keys(toolExecutors);
}

/** Check if a tool exists */
export function toolExists(toolName: string): boolean {
  return toolName in toolExecutors;
}
