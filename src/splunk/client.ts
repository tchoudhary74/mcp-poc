/** Splunk REST API client */

import { AxiosInstance } from 'axios';
import { settings } from '../config.js';
import { createChildLogger } from '../logging/logger.js';
import {
  Credentials,
  SplunkAPIError,
  Event,
  EventSchema,
  SplunkIndex,
  SplunkSavedSearch,
  SplunkAlert,
} from '../types.js';
import { authenticate, createAuthenticatedClient, AuthResult, validateAuth } from './auth.js';
import {
  SplunkJobStatus,
  SplunkRawEvent,
  SplunkResultsResponse,
  SplunkIndexInfo,
  SplunkSavedSearchInfo,
  SplunkFiredAlertInfo,
  SearchOptions,
} from './types.js';

const logger = createChildLogger('splunk-client');

/** Search result with metadata */
export interface SearchResult {
  events: Event[];
  totalCount: number;
  searchId: string;
  executionTimeMs: number;
  truncated: boolean;
}

export class SplunkClient {
  private client: AxiosInstance | null = null;
  private authResult: AuthResult | null = null;
  private credentials: Credentials;

  constructor(credentials: Credentials) {
    this.credentials = credentials;
  }

  /**
   * Initialize the client by authenticating with Splunk.
   */
  async initialize(): Promise<void> {
    this.authResult = await authenticate(this.credentials);
    this.client = createAuthenticatedClient(this.authResult);
    logger.info('Splunk client initialized');
  }

  /**
   * Ensure the client is authenticated and return the Axios instance.
   */
  private async getClient(): Promise<AxiosInstance> {
    if (!this.client || !this.authResult) {
      await this.initialize();
    }

    // Check if session is expired
    if (this.authResult?.expiresAt && this.authResult.expiresAt < new Date()) {
      logger.info('Session expired, re-authenticating');
      await this.initialize();
    }

    return this.client!;
  }

  /**
   * Validate connection to Splunk.
   */
  async healthCheck(): Promise<boolean> {
    try {
      const client = await this.getClient();
      return await validateAuth(client);
    } catch (error) {
      logger.error('Health check failed', {
        error: error instanceof Error ? error.message : String(error),
      });
      return false;
    }
  }

  /**
   * Execute a search and return results.
   */
  async search(query: string, options: SearchOptions = {}): Promise<SearchResult> {
    const startTime = Date.now();
    const client = await this.getClient();

    const {
      earliestTime = settings.defaultEarliestTime,
      latestTime = settings.defaultLatestTime,
      maxResults = settings.maxResults,
      timeout = settings.searchTimeout,
      app = settings.splunkApp,
      owner = settings.splunkOwner,
    } = options;

    logger.debug('Executing search', { query, earliestTime, latestTime, maxResults });

    // Create search job
    const createResponse = await client.post(
      `/servicesNS/${owner}/${app}/search/jobs`,
      new URLSearchParams({
        search: query.startsWith('search ') ? query : `search ${query}`,
        earliest_time: earliestTime,
        latest_time: latestTime,
        output_mode: 'json',
        max_count: String(maxResults),
      }).toString()
    );

    const sid = createResponse.data?.sid;
    if (!sid) {
      throw new SplunkAPIError('No search ID returned');
    }

    logger.debug('Search job created', { sid });

    // Wait for search to complete
    await this.waitForJob(sid, timeout);

    // Get results
    const resultsResponse = await client.get<SplunkResultsResponse>(
      `/servicesNS/${owner}/${app}/search/jobs/${sid}/results`,
      {
        params: {
          output_mode: 'json',
          count: maxResults,
        },
      }
    );

    const rawEvents = resultsResponse.data?.results || [];
    const events = this.parseEvents(rawEvents);
    const executionTimeMs = Date.now() - startTime;

    // Get job status for total count
    const status = await this.getJobStatus(sid);

    logger.info('Search completed', {
      sid,
      eventCount: events.length,
      totalCount: status.resultCount,
      executionTimeMs,
    });

    return {
      events,
      totalCount: status.resultCount,
      searchId: sid,
      executionTimeMs,
      truncated: status.resultCount > maxResults,
    };
  }

  /**
   * Wait for a search job to complete.
   */
  private async waitForJob(sid: string, timeout: number): Promise<void> {
    const client = await this.getClient();
    const startTime = Date.now();
    const pollInterval = 500; // 500ms

    while (Date.now() - startTime < timeout * 1000) {
      const status = await this.getJobStatus(sid);

      if (status.isDone) {
        if (status.isFailed) {
          const errorMsg = status.messages
            .filter((m) => m.type === 'ERROR' || m.type === 'FATAL')
            .map((m) => m.text)
            .join('; ');
          throw new SplunkAPIError(`Search job failed: ${errorMsg || 'Unknown error'}`);
        }
        return;
      }

      await new Promise((resolve) => setTimeout(resolve, pollInterval));
    }

    // Timeout - try to cancel the job
    try {
      await client.delete(`/services/search/jobs/${sid}`);
    } catch {
      // Ignore cancel errors
    }

    throw new SplunkAPIError(`Search job timed out after ${timeout} seconds`, undefined, true);
  }

  /**
   * Get job status.
   */
  private async getJobStatus(sid: string): Promise<SplunkJobStatus> {
    const client = await this.getClient();
    const response = await client.get(`/services/search/jobs/${sid}`, {
      params: { output_mode: 'json' },
    });

    const entry = response.data?.entry?.[0]?.content;
    if (!entry) {
      throw new SplunkAPIError('Invalid job status response');
    }

    return {
      sid,
      dispatchState: entry.dispatchState,
      doneProgress: entry.doneProgress,
      scanCount: entry.scanCount,
      eventCount: entry.eventCount,
      resultCount: entry.resultCount,
      isDone: entry.isDone,
      isFailed: entry.isFailed,
      isFinalized: entry.isFinalized,
      isPaused: entry.isPaused,
      isPreviewEnabled: entry.isPreviewEnabled,
      isRealTimeSearch: entry.isRealTimeSearch,
      isSaved: entry.isSaved,
      isZombie: entry.isZombie,
      messages: entry.messages || [],
    };
  }

  /**
   * Parse raw Splunk events into typed Event objects.
   */
  private parseEvents(rawEvents: SplunkRawEvent[]): Event[] {
    const events: Event[] = [];

    for (const raw of rawEvents) {
      const { _time, _raw, _indextime, host, source, sourcetype, index, ...rest } = raw;

      const event = EventSchema.safeParse({
        _time: _time || '',
        _raw: _raw || '',
        _indextime,
        host,
        source,
        sourcetype,
        index,
        fields: rest,
      });

      if (event.success) {
        events.push(event.data);
      } else {
        logger.warn('Failed to parse event', { error: event.error.message });
      }
    }

    return events;
  }

  /**
   * List available indexes.
   */
  async listIndexes(filter?: string): Promise<SplunkIndex[]> {
    const client = await this.getClient();

    const response = await client.get('/services/data/indexes', {
      params: {
        output_mode: 'json',
        count: 0, // Get all
      },
    });

    const entries: SplunkIndexInfo[] = response.data?.entry || [];
    let indexes: SplunkIndex[] = entries
      .filter((e) => !e.content.disabled && !e.content.isInternal)
      .map((e) => ({
        name: e.name,
        totalEventCount: e.content.totalEventCount,
        currentDBSizeMB: e.content.currentDBSizeMB,
        maxDataSizeMB: e.content.maxDataSizeMB,
        frozenTimePeriodInSecs: e.content.frozenTimePeriodInSecs,
      }));

    if (filter) {
      const filterLower = filter.toLowerCase();
      indexes = indexes.filter((i) => i.name.toLowerCase().includes(filterLower));
    }

    logger.info('Listed indexes', { count: indexes.length });
    return indexes;
  }

  /**
   * List saved searches.
   */
  async listSavedSearches(app?: string, owner?: string): Promise<SplunkSavedSearch[]> {
    const client = await this.getClient();

    const targetApp = app || settings.splunkApp;
    const targetOwner = owner || '-'; // '-' means all owners

    const response = await client.get(
      `/servicesNS/${targetOwner}/${targetApp}/saved/searches`,
      {
        params: {
          output_mode: 'json',
          count: 0,
        },
      }
    );

    const entries: SplunkSavedSearchInfo[] = response.data?.entry || [];
    const savedSearches: SplunkSavedSearch[] = entries.map((e) => ({
      name: e.name,
      search: e.content.search,
      description: e.content.description || '',
      app: e.content['eai:acl'].app,
      owner: e.content['eai:acl'].owner,
      isScheduled: e.content.is_scheduled,
      cronSchedule: e.content.cron_schedule,
    }));

    logger.info('Listed saved searches', { count: savedSearches.length });
    return savedSearches;
  }

  /**
   * Run a saved search.
   */
  async runSavedSearch(
    name: string,
    earliestTime?: string,
    latestTime?: string
  ): Promise<SearchResult> {
    const client = await this.getClient();
    const startTime = Date.now();

    const params: Record<string, string> = {
      output_mode: 'json',
    };

    if (earliestTime) params['dispatch.earliest_time'] = earliestTime;
    if (latestTime) params['dispatch.latest_time'] = latestTime;

    // Dispatch the saved search
    const dispatchResponse = await client.post(
      `/servicesNS/-/${settings.splunkApp}/saved/searches/${encodeURIComponent(name)}/dispatch`,
      new URLSearchParams(params).toString()
    );

    const sid = dispatchResponse.data?.sid;
    if (!sid) {
      throw new SplunkAPIError('No search ID returned from saved search dispatch');
    }

    // Wait for completion
    await this.waitForJob(sid, settings.searchTimeout);

    // Get results
    const resultsResponse = await client.get<SplunkResultsResponse>(
      `/services/search/jobs/${sid}/results`,
      {
        params: {
          output_mode: 'json',
          count: settings.maxResults,
        },
      }
    );

    const rawEvents = resultsResponse.data?.results || [];
    const events = this.parseEvents(rawEvents);
    const status = await this.getJobStatus(sid);

    return {
      events,
      totalCount: status.resultCount,
      searchId: sid,
      executionTimeMs: Date.now() - startTime,
      truncated: status.resultCount > settings.maxResults,
    };
  }

  /**
   * List fired alerts.
   */
  async listFiredAlerts(
    severity?: string,
    earliestTime?: string
  ): Promise<SplunkAlert[]> {
    const client = await this.getClient();

    const response = await client.get('/services/alerts/fired_alerts', {
      params: {
        output_mode: 'json',
        count: 0,
      },
    });

    const entries: SplunkFiredAlertInfo[] = response.data?.entry || [];
    let alerts: SplunkAlert[] = entries.map((e) => ({
      name: e.name,
      severity: e.content.severity,
      triggeredTime: e.content.trigger_time,
      message: e.content.message || '',
      app: e.content['eai:acl'].app,
      resultCount: e.content.triggered_alerts,
    }));

    // Filter by severity if specified
    if (severity) {
      alerts = alerts.filter(
        (a) => a.severity.toLowerCase() === severity.toLowerCase()
      );
    }

    // Filter by time if specified
    if (earliestTime) {
      // This is a simplified filter - in production you'd parse the time properly
      const earliest = this.parseRelativeTime(earliestTime);
      if (earliest) {
        alerts = alerts.filter((a) => new Date(a.triggeredTime) >= earliest);
      }
    }

    logger.info('Listed fired alerts', { count: alerts.length });
    return alerts;
  }

  /**
   * Parse a relative time string into a Date.
   */
  private parseRelativeTime(timeStr: string): Date | null {
    const now = new Date();
    const match = timeStr.match(/^-(\d+)([smhd])$/);

    if (!match) return null;

    const value = parseInt(match[1], 10);
    const unit = match[2];

    switch (unit) {
      case 's':
        return new Date(now.getTime() - value * 1000);
      case 'm':
        return new Date(now.getTime() - value * 60 * 1000);
      case 'h':
        return new Date(now.getTime() - value * 60 * 60 * 1000);
      case 'd':
        return new Date(now.getTime() - value * 24 * 60 * 60 * 1000);
      default:
        return null;
    }
  }
}
