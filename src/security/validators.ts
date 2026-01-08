/** Input validation helpers for Splunk queries */

/**
 * Check if a value is a valid identifier (index name, field name, etc.)
 * Only allows alphanumeric characters, underscores, hyphens, and dots.
 */
export function isValidIdentifier(value: string): boolean {
  if (!value || typeof value !== 'string') return false;
  return /^[a-zA-Z0-9_\-\.]+$/.test(value);
}

/**
 * Check if a value is a valid event ID.
 * Event IDs can contain alphanumeric chars, underscores, hyphens, dots, and colons.
 */
export function isValidEventId(value: string): boolean {
  if (!value || typeof value !== 'string') return false;
  return /^[a-zA-Z0-9_\-\.:]+$/.test(value) && value.length <= 256;
}

/**
 * Check if a value is a valid Splunk time specification.
 * Examples: -24h, -7d, now, 2024-01-01T00:00:00, @d
 */
export function isValidTimeSpec(value: string): boolean {
  if (!value || typeof value !== 'string') return false;

  // Relative time: -24h, -7d, -30m, etc.
  if (/^-\d+[smhdwMy]$/.test(value)) return true;

  // Snap time: @d, @h, @w0, etc.
  if (/^@[smhdwMy]\d*$/.test(value)) return true;

  // "now" keyword
  if (value === 'now') return true;

  // ISO 8601 format
  if (/^\d{4}-\d{2}-\d{2}(T\d{2}:\d{2}:\d{2}(Z|[+-]\d{2}:\d{2})?)?$/.test(value)) return true;

  // Epoch time
  if (/^\d{10,13}$/.test(value)) return true;

  return false;
}

/**
 * Escape special characters in a string for use in SPL.
 * This prevents SPL injection by escaping metacharacters.
 */
export function escapeSPLString(value: string): string {
  if (!value) return '';

  return value
    .replace(/\\/g, '\\\\')      // Escape backslashes first
    .replace(/"/g, '\\"')        // Escape double quotes
    .replace(/'/g, "\\'")        // Escape single quotes
    .replace(/\|/g, '\\|')       // Escape pipe (SPL command separator)
    .replace(/;/g, '\\;')        // Escape semicolon
    .replace(/`/g, '\\`')        // Escape backtick (used for macros)
    .replace(/\$/g, '\\$')       // Escape dollar sign (used for variables)
    .replace(/\[/g, '\\[')       // Escape brackets (used for subsearches)
    .replace(/\]/g, '\\]');
}

/**
 * Sanitize a search query by removing or escaping dangerous patterns.
 * This is a last-resort measure - prefer using the security scanner.
 */
export function sanitizeQuery(query: string): string {
  if (!query) return '';

  let sanitized = query;

  // Remove script/code blocks
  sanitized = sanitized.replace(/<script[^>]*>[\s\S]*?<\/script>/gi, '');
  sanitized = sanitized.replace(/```[\s\S]*?```/g, '');

  // Normalize whitespace
  sanitized = sanitized.replace(/\s+/g, ' ').trim();

  return sanitized;
}

/**
 * Validate a field name is safe for use in SPL.
 */
export function isValidFieldName(value: string): boolean {
  if (!value || typeof value !== 'string') return false;
  // Field names: alphanumeric, underscores, must start with letter or underscore
  return /^[a-zA-Z_][a-zA-Z0-9_]*$/.test(value) && value.length <= 100;
}

/**
 * Validate a hostname.
 */
export function isValidHostname(value: string): boolean {
  if (!value || typeof value !== 'string') return false;
  // Basic hostname validation
  return /^[a-zA-Z0-9][a-zA-Z0-9\-\.]*[a-zA-Z0-9]$/.test(value) && value.length <= 253;
}

/**
 * Validate a source path.
 */
export function isValidSourcePath(value: string): boolean {
  if (!value || typeof value !== 'string') return false;
  // Allow typical file paths but block injection attempts
  if (value.includes('..')) return false;
  if (/[<>|;&]/.test(value)) return false;
  return value.length <= 1024;
}
