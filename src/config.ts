/** Configuration management for the Splunk MCP Server */

import dotenv from 'dotenv';

// Load environment variables
dotenv.config();

/** Parse a string environment variable with a default */
function parseString(value: string | undefined, defaultValue: string): string {
  return value?.trim() || defaultValue;
}

/** Parse a boolean environment variable */
function parseBoolean(value: string | undefined, defaultValue: boolean): boolean {
  if (!value) return defaultValue;
  return value.toLowerCase() === 'true' || value === '1';
}

/** Parse an integer environment variable */
function parseInteger(value: string | undefined, defaultValue: number): number {
  if (!value) return defaultValue;
  const parsed = parseInt(value, 10);
  return isNaN(parsed) ? defaultValue : parsed;
}

/** Parse a float environment variable */
function parseFloatValue(value: string | undefined, defaultValue: number): number {
  if (!value) return defaultValue;
  const parsed = Number.parseFloat(value);
  return isNaN(parsed) ? defaultValue : parsed;
}

/** Application settings derived from environment variables */
export const settings = {
  // Splunk connection
  splunkHost: parseString(process.env.SPLUNK_HOST, 'https://localhost:8089'),
  splunkToken: process.env.SPLUNK_TOKEN,
  splunkUsername: process.env.SPLUNK_USERNAME,
  splunkPassword: process.env.SPLUNK_PASSWORD,
  splunkApp: parseString(process.env.SPLUNK_APP, 'search'),
  splunkOwner: parseString(process.env.SPLUNK_OWNER, 'admin'),
  splunkVerifySSL: parseBoolean(process.env.SPLUNK_VERIFY_SSL, true),
  splunkTimeout: parseInteger(process.env.SPLUNK_TIMEOUT, 30000),

  // AWS Secrets Manager (optional)
  awsSecretsSecretName: process.env.AWS_SECRETS_SECRET_NAME,
  awsSecretsRegion: parseString(process.env.AWS_SECRETS_REGION, 'us-east-1'),

  // Search defaults
  maxResults: parseInteger(process.env.MAX_RESULTS, 1000),
  defaultEarliestTime: parseString(process.env.DEFAULT_EARLIEST_TIME, '-24h'),
  defaultLatestTime: parseString(process.env.DEFAULT_LATEST_TIME, 'now'),
  searchTimeout: parseInteger(process.env.SEARCH_TIMEOUT, 300),

  // Trust scoring
  trustThresholdProceed: parseFloatValue(process.env.TRUST_THRESHOLD_PROCEED, 0.7),
  trustThresholdCaution: parseFloatValue(process.env.TRUST_THRESHOLD_CAUTION, 0.4),

  // Logging
  logLevel: parseString(process.env.LOG_LEVEL, 'info'),
  enableAuditLog: parseBoolean(process.env.ENABLE_AUDIT_LOG, true),

  // Server
  etlVersion: parseString(process.env.ETL_VERSION, '1.0.0'),
} as const;

/** Validate required configuration at startup */
export function validateConfig(): void {
  const errors: string[] = [];

  // Check Splunk host
  if (!settings.splunkHost) {
    errors.push('SPLUNK_HOST is required');
  }

  // Check credentials - at least one method must be configured
  const hasToken = !!settings.splunkToken;
  const hasUserPass = !!(settings.splunkUsername && settings.splunkPassword);
  const hasAWSSecrets = !!settings.awsSecretsSecretName;

  if (!hasToken && !hasUserPass && !hasAWSSecrets) {
    errors.push(
      'No credentials configured. Set SPLUNK_TOKEN, or SPLUNK_USERNAME + SPLUNK_PASSWORD, or AWS_SECRETS_SECRET_NAME'
    );
  }

  // Validate thresholds
  if (settings.trustThresholdProceed <= settings.trustThresholdCaution) {
    errors.push('TRUST_THRESHOLD_PROCEED must be greater than TRUST_THRESHOLD_CAUTION');
  }

  if (errors.length > 0) {
    throw new Error(`Configuration errors:\n${errors.map((e) => `  - ${e}`).join('\n')}`);
  }
}

/** Get a safe representation of config for logging (no secrets) */
export function getSafeConfig(): Record<string, unknown> {
  return {
    splunkHost: settings.splunkHost,
    splunkApp: settings.splunkApp,
    splunkOwner: settings.splunkOwner,
    splunkVerifySSL: settings.splunkVerifySSL,
    splunkTimeout: settings.splunkTimeout,
    hasToken: !!settings.splunkToken,
    hasUserPass: !!(settings.splunkUsername && settings.splunkPassword),
    hasAWSSecrets: !!settings.awsSecretsSecretName,
    maxResults: settings.maxResults,
    defaultEarliestTime: settings.defaultEarliestTime,
    defaultLatestTime: settings.defaultLatestTime,
    searchTimeout: settings.searchTimeout,
    trustThresholdProceed: settings.trustThresholdProceed,
    trustThresholdCaution: settings.trustThresholdCaution,
    logLevel: settings.logLevel,
    enableAuditLog: settings.enableAuditLog,
    etlVersion: settings.etlVersion,
  };
}
