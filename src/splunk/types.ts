/** Splunk-specific API types and interfaces */

/** Splunk search job status */
export interface SplunkJobStatus {
  sid: string;
  dispatchState: string;
  doneProgress: number;
  scanCount: number;
  eventCount: number;
  resultCount: number;
  isDone: boolean;
  isFailed: boolean;
  isFinalized: boolean;
  isPaused: boolean;
  isPreviewEnabled: boolean;
  isRealTimeSearch: boolean;
  isSaved: boolean;
  isZombie: boolean;
  messages: Array<{ type: string; text: string }>;
}

/** Splunk search job creation response */
export interface SplunkJobCreateResponse {
  sid: string;
}

/** Splunk raw event from API */
export interface SplunkRawEvent {
  _time: string;
  _raw: string;
  _indextime?: string;
  host?: string;
  source?: string;
  sourcetype?: string;
  index?: string;
  [key: string]: unknown;
}

/** Splunk search results response */
export interface SplunkResultsResponse {
  results: SplunkRawEvent[];
  init_offset: number;
  messages: Array<{ type: string; text: string }>;
  preview: boolean;
}

/** Splunk index info from REST API */
export interface SplunkIndexInfo {
  name: string;
  content: {
    totalEventCount: string;
    currentDBSizeMB: string;
    maxDataSizeMB: string;
    frozenTimePeriodInSecs: string;
    disabled: boolean;
    isInternal: boolean;
  };
}

/** Splunk saved search info from REST API */
export interface SplunkSavedSearchInfo {
  name: string;
  content: {
    search: string;
    description: string;
    'eai:acl': {
      app: string;
      owner: string;
    };
    is_scheduled: boolean;
    cron_schedule?: string;
  };
}

/** Splunk fired alert info from REST API */
export interface SplunkFiredAlertInfo {
  name: string;
  content: {
    severity: string;
    trigger_time: string;
    message?: string;
    triggered_alerts: number;
    'eai:acl': {
      app: string;
    };
  };
}

/** Search options for creating a search job */
export interface SearchOptions {
  earliestTime?: string;
  latestTime?: string;
  maxResults?: number;
  timeout?: number;
  app?: string;
  owner?: string;
}

/** Authentication mode */
export enum AuthMode {
  TOKEN = 'token',
  SESSION = 'session',
}

/** Session info for session-based auth */
export interface SessionInfo {
  sessionKey: string;
  expiresAt: Date;
}
