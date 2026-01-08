/** Shared types and Zod schemas for the Splunk MCP Server */

import { z } from 'zod';

// =============================================================================
// Credential Types
// =============================================================================

export const CredentialsSchema = z.object({
  token: z.string().optional(),
  username: z.string().optional(),
  password: z.string().optional(),
}).refine(
  (data) => data.token || (data.username && data.password),
  { message: 'Either token or username/password is required' }
);

export type Credentials = z.infer<typeof CredentialsSchema>;

// =============================================================================
// Splunk Event Types
// =============================================================================

export const EventSchema = z.object({
  _time: z.string(),
  _raw: z.string(),
  _indextime: z.string().optional(),
  host: z.string().optional(),
  source: z.string().optional(),
  sourcetype: z.string().optional(),
  index: z.string().optional(),
  fields: z.record(z.unknown()).default({}),
});

export type Event = z.infer<typeof EventSchema>;

export const SplunkSearchResultSchema = z.object({
  events: z.array(EventSchema),
  totalEvents: z.number(),
  returnedEvents: z.number(),
  truncated: z.boolean(),
  searchId: z.string(),
  executionTimeMs: z.number(),
  error: z.string().optional(),
  aggregations: z.record(z.unknown()).optional(),
});

export type SplunkSearchResult = z.infer<typeof SplunkSearchResultSchema>;

// =============================================================================
// Trust Types
// =============================================================================

export enum TrustThresholdDecision {
  PROCEED = 'PROCEED',
  CAUTION = 'CAUTION',
  DONT_RELY = 'DONT_RELY',
}

export const TrustDimensionSchema = z.object({
  authority: z.number().min(0).max(1),
  freshness: z.number().min(0).max(1),
  completeness: z.number().min(0).max(1),
  coherence: z.number().min(0).max(1),
  integrity: z.number().min(0).max(1),
  trackRecord: z.number().min(0).max(1),
  corroboration: z.number().min(0).max(1).optional(),
});

export type TrustDimension = z.infer<typeof TrustDimensionSchema>;

export const TrustFactorsSchema = z.object({
  factors: z.array(z.string()),
  warnings: z.array(z.string()),
  missingFields: z.array(z.string()),
});

export type TrustFactors = z.infer<typeof TrustFactorsSchema>;

export const TrustMetadataSchema = z.object({
  compositeScore: z.number().min(0).max(1),
  thresholdDecision: z.nativeEnum(TrustThresholdDecision),
  dimensions: TrustDimensionSchema,
  factors: TrustFactorsSchema,
  agentDirective: z.string(),
  computedAt: z.date(),
});

export type TrustMetadata = z.infer<typeof TrustMetadataSchema>;

// =============================================================================
// Tool Input Types
// =============================================================================

export const SearchInputSchema = z.object({
  query: z.string().min(1, 'Query is required'),
  earliest_time: z.string().default('-24h'),
  latest_time: z.string().default('now'),
  max_results: z.number().min(1).max(10000).default(1000),
  index: z.string().optional(),
});

export type SearchInput = z.infer<typeof SearchInputSchema>;

export const GetEventsInputSchema = z.object({
  index: z.string().min(1, 'Index is required'),
  earliest_time: z.string().default('-24h'),
  latest_time: z.string().default('now'),
  max_results: z.number().min(1).max(10000).default(100),
  source: z.string().optional(),
  sourcetype: z.string().optional(),
  host: z.string().optional(),
});

export type GetEventsInput = z.infer<typeof GetEventsInputSchema>;

export const CorrelateInputSchema = z.object({
  event_id: z.string().min(1, 'Event ID is required'),
  time_window: z.string().default('5m'),
  correlation_fields: z.array(z.string()).default(['host', 'source', 'user']),
  max_results: z.number().min(1).max(1000).default(100),
});

export type CorrelateInput = z.infer<typeof CorrelateInputSchema>;

export const GetContextInputSchema = z.object({
  event_id: z.string().min(1, 'Event ID is required'),
  before_count: z.number().min(0).max(100).default(10),
  after_count: z.number().min(0).max(100).default(10),
});

export type GetContextInput = z.infer<typeof GetContextInputSchema>;

export const ListIndexesInputSchema = z.object({
  filter: z.string().optional(),
});

export type ListIndexesInput = z.infer<typeof ListIndexesInputSchema>;

export const ListSavedSearchesInputSchema = z.object({
  app: z.string().optional(),
  owner: z.string().optional(),
});

export type ListSavedSearchesInput = z.infer<typeof ListSavedSearchesInputSchema>;

export const RunSavedSearchInputSchema = z.object({
  name: z.string().min(1, 'Saved search name is required'),
  earliest_time: z.string().optional(),
  latest_time: z.string().optional(),
});

export type RunSavedSearchInput = z.infer<typeof RunSavedSearchInputSchema>;

export const ListAlertsInputSchema = z.object({
  severity: z.enum(['info', 'low', 'medium', 'high', 'critical']).optional(),
  earliest_time: z.string().default('-24h'),
});

export type ListAlertsInput = z.infer<typeof ListAlertsInputSchema>;

// =============================================================================
// Splunk API Response Types
// =============================================================================

export interface SplunkIndex {
  name: string;
  totalEventCount: string;
  currentDBSizeMB: string;
  maxDataSizeMB: string;
  frozenTimePeriodInSecs: string;
}

export interface SplunkSavedSearch {
  name: string;
  search: string;
  description: string;
  app: string;
  owner: string;
  isScheduled: boolean;
  cronSchedule?: string;
}

export interface SplunkAlert {
  name: string;
  severity: string;
  triggeredTime: string;
  message: string;
  app: string;
  resultCount: number;
}

// =============================================================================
// Error Types
// =============================================================================

export class SplunkMCPError extends Error {
  public readonly code: string;
  public readonly isSecurityError: boolean;
  public readonly isRetryable: boolean;

  constructor(
    message: string,
    code: string,
    isSecurityError = false,
    isRetryable = false
  ) {
    super(message);
    this.name = 'SplunkMCPError';
    this.code = code;
    this.isSecurityError = isSecurityError;
    this.isRetryable = isRetryable;
  }
}

export class SecurityError extends SplunkMCPError {
  constructor(message: string, code = 'SECURITY_ERROR') {
    super(message, code, true, false);
    this.name = 'SecurityError';
  }
}

export class InjectionError extends SecurityError {
  constructor(message: string) {
    super(message, 'INJECTION_DETECTED');
    this.name = 'InjectionError';
  }
}

export class ReadOnlyViolationError extends SecurityError {
  constructor(message: string) {
    super(message, 'READ_ONLY_VIOLATION');
    this.name = 'ReadOnlyViolationError';
  }
}

export class ValidationError extends SplunkMCPError {
  constructor(message: string) {
    super(message, 'VALIDATION_ERROR', false, false);
    this.name = 'ValidationError';
  }
}

export class AuthenticationError extends SplunkMCPError {
  constructor(message: string) {
    super(message, 'AUTH_ERROR', false, false);
    this.name = 'AuthenticationError';
  }
}

export class SplunkAPIError extends SplunkMCPError {
  public readonly statusCode?: number;

  constructor(message: string, statusCode?: number, isRetryable = false) {
    super(message, 'SPLUNK_API_ERROR', false, isRetryable);
    this.name = 'SplunkAPIError';
    this.statusCode = statusCode;
  }
}
