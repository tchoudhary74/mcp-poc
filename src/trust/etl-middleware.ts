/** ETL Middleware for trust scoring and directive generation */

import { parseISO, differenceInHours } from 'date-fns';
import { settings } from '../config.js';
import {
  TrustMetadata,
  TrustDimension,
  TrustFactors,
  TrustThresholdDecision,
  SplunkSearchResult,
  Event,
  TrustMetadataSchema,
  TrustDimensionSchema,
  TrustFactorsSchema,
} from '../types.js';
import { createChildLogger } from '../logging/logger.js';

const logger = createChildLogger('etl-middleware');

/** Internal interface for completeness computation result */
interface CompletenessResult {
  score: number;
  missingFields: string[];
}

/**
 * ETL Middleware for computing trust scores on search results.
 *
 * Trust scoring helps AI agents understand the reliability and quality
 * of the data they're working with, enabling better decision-making.
 */
export class ETLMiddleware {
  private readonly etlVersion: string;
  private trustThresholdProceed: number;
  private trustThresholdCaution: number;

  // Store missing fields from last computation
  private lastMissingFields: string[] = [];

  constructor() {
    this.etlVersion = settings.etlVersion;
    this.trustThresholdProceed = settings.trustThresholdProceed;
    this.trustThresholdCaution = settings.trustThresholdCaution;
  }

  /** Get the ETL version */
  getVersion(): string {
    return this.etlVersion;
  }

  /**
   * Compute trust metadata for a search result.
   */
  computeTrust(result: SplunkSearchResult): TrustMetadata {
    const startTime = Date.now();

    // Reset missing fields for this computation
    this.lastMissingFields = [];

    // Compute individual trust dimensions
    const dimensions = this.computeDimensions(result);

    // Compute composite score (weighted average)
    const weights = {
      authority: 0.2,
      freshness: 0.2,
      completeness: 0.2,
      coherence: 0.15,
      integrity: 0.15,
      trackRecord: 0.1,
    };

    let compositeScore =
      dimensions.authority * weights.authority +
      dimensions.freshness * weights.freshness +
      dimensions.completeness * weights.completeness +
      dimensions.coherence * weights.coherence +
      dimensions.integrity * weights.integrity +
      dimensions.trackRecord * weights.trackRecord;

    // Add corroboration if available
    if (dimensions.corroboration !== undefined) {
      compositeScore = compositeScore * 0.9 + dimensions.corroboration * 0.1;
    }

    // Determine threshold decision
    const thresholdDecision = this.determineThresholdDecision(compositeScore);

    // Generate factors and warnings
    const factors = this.generateFactors(result, dimensions);

    // Generate agent directive
    const agentDirective = this.generateDirective(thresholdDecision, compositeScore, factors);

    const etlTime = Date.now() - startTime;

    logger.info('Trust computed', {
      compositeScore: compositeScore.toFixed(3),
      thresholdDecision,
      etlTimeMs: etlTime,
    });

    return TrustMetadataSchema.parse({
      compositeScore,
      thresholdDecision,
      dimensions,
      factors,
      agentDirective,
      computedAt: new Date(),
    });
  }

  private computeDimensions(result: SplunkSearchResult): TrustDimension {
    // Compute completeness first to capture missing fields
    const completenessResult = this.computeCompletenessWithDetails(result);
    this.lastMissingFields = completenessResult.missingFields;

    return TrustDimensionSchema.parse({
      authority: this.computeAuthority(result),
      freshness: this.computeFreshness(result),
      trackRecord: this.computeTrackRecord(result),
      completeness: completenessResult.score,
      coherence: this.computeCoherence(result),
      integrity: this.computeIntegrity(result),
      corroboration: this.computeCorroboration(),
    });
  }

  private computeAuthority(result: SplunkSearchResult): number {
    let score = 0.8; // Base score for Splunk data

    // Boost if search job succeeded
    if (result.searchId && !result.error) {
      score += 0.1;
    }

    // Boost if aggregations are available
    if (result.aggregations) {
      score += 0.1;
    }

    return Math.min(1.0, score);
  }

  private computeFreshness(result: SplunkSearchResult): number {
    if (result.events.length === 0) {
      return 0.5; // Neutral if no events
    }

    const now = new Date();
    let recentCount = 0;
    let totalCount = 0;

    for (const event of result.events) {
      try {
        let timeStr = event._time;
        if (timeStr.includes('.')) {
          timeStr = timeStr.split('.')[0];
        }

        const eventTime = parseISO(timeStr);
        const ageHours = differenceInHours(now, eventTime);
        totalCount++;

        if (ageHours <= 24) {
          recentCount++;
        }
      } catch {
        // Skip if time parsing fails
      }
    }

    if (totalCount === 0) {
      return 0.5;
    }

    return recentCount / totalCount;
  }

  private computeCompletenessWithDetails(result: SplunkSearchResult): CompletenessResult {
    if (result.events.length === 0) {
      return { score: 0.0, missingFields: [] };
    }

    const requiredFields = ['_time', '_raw'];
    const commonFields = ['source', 'host', 'sourcetype'];

    let completeCount = 0;
    let totalCount = 0;
    const missingFields: string[] = [];

    for (const event of result.events) {
      totalCount++;
      let eventComplete = true;

      // Check required fields
      if (!event._time || !event._raw) {
        eventComplete = false;
        for (const field of requiredFields) {
          if (!event[field as keyof Event]) {
            missingFields.push(field);
          }
        }
      }

      // Check common fields
      const commonMissing = commonFields.filter((f) => !event[f as keyof Event]);
      if (commonMissing.length > 1) {
        eventComplete = false;
        missingFields.push(...commonMissing);
      }

      if (eventComplete) {
        completeCount++;
      }
    }

    const score = totalCount > 0 ? completeCount / totalCount : 0.0;
    return { score, missingFields: [...new Set(missingFields)] };
  }

  private computeCoherence(result: SplunkSearchResult): number {
    if (result.events.length === 0) {
      return 0.5;
    }

    let score = 1.0;

    // Check for structural consistency
    const fieldCounts: Record<string, number> = {};
    for (const event of result.events) {
      const fieldKey = Object.keys(event.fields).sort().join(',');
      fieldCounts[fieldKey] = (fieldCounts[fieldKey] || 0) + 1;
    }

    // If events have very different structures, reduce coherence
    if (Object.keys(fieldCounts).length > 1) {
      const maxVariance = Math.max(...Object.values(fieldCounts)) / result.events.length;
      if (maxVariance < 0.8) {
        score -= 0.2;
      }
    }

    // Penalize if truncated
    if (result.truncated) {
      score -= 0.1;
    }

    return Math.max(0.0, Math.min(1.0, score));
  }

  private computeIntegrity(result: SplunkSearchResult): number {
    let score = 1.0;

    // Penalize if there's an error
    if (result.error) {
      score -= 0.5;
    }

    // Check for data validation issues
    if (result.events.length > 0) {
      let invalidCount = 0;
      for (const event of result.events) {
        if (!event._raw || event._raw.trim().length === 0) {
          invalidCount++;
        }
      }

      const invalidRatio = invalidCount / result.events.length;
      score -= invalidRatio * 0.3;
    }

    // Boost if search execution was successful
    if (result.searchId && result.executionTimeMs > 0) {
      if (result.executionTimeMs < 100) {
        score += 0.05;
      }
    }

    return Math.max(0.0, Math.min(1.0, score));
  }

  private computeTrackRecord(result: SplunkSearchResult): number {
    let score = 0.7; // Base score

    // Boost if search completed successfully
    if (result.searchId && !result.error) {
      score += 0.2;
    }

    // Boost if execution was fast
    if (result.executionTimeMs > 0 && result.executionTimeMs < 5000) {
      score += 0.1;
    }

    return Math.min(1.0, score);
  }

  private computeCorroboration(): number | undefined {
    // Not implemented - would cross-reference with other data sources
    return undefined;
  }

  private determineThresholdDecision(compositeScore: number): TrustThresholdDecision {
    if (compositeScore >= this.trustThresholdProceed) {
      return TrustThresholdDecision.PROCEED;
    } else if (compositeScore >= this.trustThresholdCaution) {
      return TrustThresholdDecision.CAUTION;
    } else {
      return TrustThresholdDecision.DONT_RELY;
    }
  }

  private generateFactors(result: SplunkSearchResult, dimensions: TrustDimension): TrustFactors {
    const factors: string[] = [];
    const warnings: string[] = [];

    // Positive factors
    if (dimensions.authority >= 0.8) {
      factors.push('High authority data source (Splunk)');
    }
    if (dimensions.freshness >= 0.7) {
      factors.push('Recent data (within 24 hours)');
    }
    if (result.aggregations) {
      factors.push('Aggregations available for analysis');
    }
    if (!result.error) {
      factors.push('Query executed successfully');
    }
    if (result.executionTimeMs < 2000) {
      factors.push('Fast query execution');
    }

    // Warnings
    if (dimensions.completeness < 0.7) {
      warnings.push(
        `Low completeness (${dimensions.completeness.toFixed(2)}): some events missing required fields`
      );
    }
    if (dimensions.freshness < 0.5) {
      warnings.push(`Stale data: freshness score ${dimensions.freshness.toFixed(2)}`);
    }
    if (result.truncated) {
      warnings.push(
        `Results truncated: ${result.returnedEvents} of ${result.totalEvents} events returned`
      );
    }
    if (result.error) {
      warnings.push(`Query error: ${result.error}`);
    }
    if (dimensions.coherence < 0.7) {
      warnings.push('Low coherence: inconsistent event structure');
    }
    if (result.executionTimeMs > 10000) {
      warnings.push(`Slow query execution: ${Math.round(result.executionTimeMs)}ms`);
    }

    return TrustFactorsSchema.parse({
      factors,
      warnings,
      missingFields: [...this.lastMissingFields],
    });
  }

  private generateDirective(
    decision: TrustThresholdDecision,
    score: number,
    factors: TrustFactors
  ): string {
    let directive: string;

    if (decision === TrustThresholdDecision.PROCEED) {
      directive = `PROCEED with confidence. Trust score: ${score.toFixed(2)}. Data quality is high and suitable for triage decisions. `;
    } else if (decision === TrustThresholdDecision.CAUTION) {
      directive = `PROCEED WITH CAUTION. Trust score: ${score.toFixed(2)}. Review the following concerns before making triage decisions: ${factors.warnings.slice(0, 3).join('; ')}. `;
    } else {
      directive = `DO NOT RELY on this data for triage decisions. Trust score: ${score.toFixed(2)}. Significant concerns: ${factors.warnings.slice(0, 3).join('; ')}. Request additional data sources or manual review.`;
    }

    if (factors.factors.length > 0) {
      directive += ` Positive factors: ${factors.factors.slice(0, 2).join(', ')}.`;
    }

    return directive;
  }
}
