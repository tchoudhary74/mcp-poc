/** Credential management for Splunk authentication */

import { settings } from '../config.js';
import { createChildLogger } from '../logging/logger.js';
import { Credentials, CredentialsSchema, AuthenticationError } from '../types.js';

const logger = createChildLogger('credential-manager');

/** Credential source for audit logging */
export enum CredentialSource {
  ENV_TOKEN = 'env_token',
  ENV_USER_PASS = 'env_user_pass',
  AWS_SECRETS = 'aws_secrets',
}

interface CredentialResult {
  credentials: Credentials;
  source: CredentialSource;
}

/**
 * Retrieve credentials from configured sources.
 * Priority: ENV_TOKEN > ENV_USER_PASS > AWS_SECRETS
 */
export async function getCredentials(): Promise<CredentialResult> {
  // Priority 1: Environment variable token
  if (settings.splunkToken) {
    logger.debug('Using token from environment variable');
    return {
      credentials: { token: settings.splunkToken },
      source: CredentialSource.ENV_TOKEN,
    };
  }

  // Priority 2: Environment variable username/password
  if (settings.splunkUsername && settings.splunkPassword) {
    logger.debug('Using username/password from environment variables');
    return {
      credentials: {
        username: settings.splunkUsername,
        password: settings.splunkPassword,
      },
      source: CredentialSource.ENV_USER_PASS,
    };
  }

  // Priority 3: AWS Secrets Manager
  if (settings.awsSecretsSecretName) {
    logger.debug('Attempting to retrieve credentials from AWS Secrets Manager');
    try {
      const credentials = await getCredentialsFromAWS(
        settings.awsSecretsSecretName,
        settings.awsSecretsRegion
      );
      return {
        credentials,
        source: CredentialSource.AWS_SECRETS,
      };
    } catch (error) {
      logger.error('Failed to retrieve credentials from AWS Secrets Manager', {
        error: error instanceof Error ? error.message : String(error),
      });
      throw new AuthenticationError(
        `Failed to retrieve credentials from AWS Secrets Manager: ${
          error instanceof Error ? error.message : String(error)
        }`
      );
    }
  }

  // No credentials found
  throw new AuthenticationError(
    'No credentials configured. Set SPLUNK_TOKEN, or SPLUNK_USERNAME + SPLUNK_PASSWORD, or AWS_SECRETS_SECRET_NAME'
  );
}

/**
 * Retrieve credentials from AWS Secrets Manager.
 * This function dynamically imports the AWS SDK to avoid requiring it when not needed.
 */
async function getCredentialsFromAWS(
  secretName: string,
  region: string
): Promise<Credentials> {
  // Dynamically import AWS SDK (it's an optional dependency)
  let SecretsManagerClient: typeof import('@aws-sdk/client-secrets-manager').SecretsManagerClient;
  let GetSecretValueCommand: typeof import('@aws-sdk/client-secrets-manager').GetSecretValueCommand;

  try {
    const awsModule = await import('@aws-sdk/client-secrets-manager');
    SecretsManagerClient = awsModule.SecretsManagerClient;
    GetSecretValueCommand = awsModule.GetSecretValueCommand;
  } catch {
    throw new Error(
      'AWS SDK not installed. Install @aws-sdk/client-secrets-manager to use AWS Secrets Manager.'
    );
  }

  const client = new SecretsManagerClient({ region });

  const response = await client.send(
    new GetSecretValueCommand({
      SecretId: secretName,
    })
  );

  if (!response.SecretString) {
    throw new Error('Secret value is empty');
  }

  // Parse the secret as JSON
  let secretData: unknown;
  try {
    secretData = JSON.parse(response.SecretString);
  } catch {
    throw new Error('Secret is not valid JSON');
  }

  // Validate against our Credentials schema
  const parseResult = CredentialsSchema.safeParse(secretData);
  if (!parseResult.success) {
    throw new Error(
      `Invalid credential format in secret: ${parseResult.error.message}`
    );
  }

  logger.info('Successfully retrieved credentials from AWS Secrets Manager', {
    secretName,
    hasToken: !!parseResult.data.token,
    hasUserPass: !!(parseResult.data.username && parseResult.data.password),
  });

  return parseResult.data;
}

/**
 * Validate that credentials are working by making a test request.
 * This is called during server startup health check.
 */
export async function validateCredentials(credentials: Credentials): Promise<boolean> {
  // This will be implemented by the Splunk client
  // For now, just validate the structure
  const parseResult = CredentialsSchema.safeParse(credentials);
  return parseResult.success;
}
