/** Splunk authentication handling */

import axios, { AxiosInstance } from 'axios';
import https from 'https';
import { settings } from '../config.js';
import { createChildLogger } from '../logging/logger.js';
import { Credentials, AuthenticationError } from '../types.js';
import { AuthMode, SessionInfo } from './types.js';

const logger = createChildLogger('splunk-auth');

/** Authentication result */
export interface AuthResult {
  mode: AuthMode;
  token?: string;
  sessionKey?: string;
  expiresAt?: Date;
}

/**
 * Create an authenticated Axios instance for Splunk API calls.
 */
export function createAuthenticatedClient(authResult: AuthResult): AxiosInstance {
  const headers: Record<string, string> = {
    'Content-Type': 'application/x-www-form-urlencoded',
    Accept: 'application/json',
  };

  if (authResult.mode === AuthMode.TOKEN && authResult.token) {
    headers['Authorization'] = `Bearer ${authResult.token}`;
  } else if (authResult.mode === AuthMode.SESSION && authResult.sessionKey) {
    headers['Authorization'] = `Splunk ${authResult.sessionKey}`;
  }

  const httpsAgent = new https.Agent({
    rejectUnauthorized: settings.splunkVerifySSL,
  });

  return axios.create({
    baseURL: settings.splunkHost,
    timeout: settings.splunkTimeout,
    headers,
    httpsAgent,
  });
}

/**
 * Authenticate with Splunk and return auth result.
 */
export async function authenticate(credentials: Credentials): Promise<AuthResult> {
  // If we have a token, use it directly
  if (credentials.token) {
    logger.debug('Using token authentication');
    return {
      mode: AuthMode.TOKEN,
      token: credentials.token,
    };
  }

  // Otherwise, get a session key using username/password
  if (credentials.username && credentials.password) {
    logger.debug('Using session authentication');
    const sessionInfo = await getSessionKey(
      credentials.username,
      credentials.password
    );
    return {
      mode: AuthMode.SESSION,
      sessionKey: sessionInfo.sessionKey,
      expiresAt: sessionInfo.expiresAt,
    };
  }

  throw new AuthenticationError('No valid credentials provided');
}

/**
 * Get a session key using username/password authentication.
 */
async function getSessionKey(
  username: string,
  password: string
): Promise<SessionInfo> {
  const httpsAgent = new https.Agent({
    rejectUnauthorized: settings.splunkVerifySSL,
  });

  try {
    const response = await axios.post(
      `${settings.splunkHost}/services/auth/login`,
      new URLSearchParams({
        username,
        password,
        output_mode: 'json',
      }).toString(),
      {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        timeout: settings.splunkTimeout,
        httpsAgent,
      }
    );

    const sessionKey = response.data?.sessionKey;
    if (!sessionKey) {
      throw new AuthenticationError('No session key in response');
    }

    logger.info('Successfully authenticated with Splunk');

    // Session expires in 1 hour by default
    const expiresAt = new Date(Date.now() + 60 * 60 * 1000);

    return {
      sessionKey,
      expiresAt,
    };
  } catch (error) {
    if (axios.isAxiosError(error)) {
      if (error.response?.status === 401) {
        throw new AuthenticationError('Invalid username or password');
      }
      throw new AuthenticationError(
        `Authentication failed: ${error.response?.data?.messages?.[0]?.text || error.message}`
      );
    }
    throw new AuthenticationError(
      `Authentication failed: ${error instanceof Error ? error.message : String(error)}`
    );
  }
}

/**
 * Validate that current authentication is still valid.
 */
export async function validateAuth(client: AxiosInstance): Promise<boolean> {
  try {
    const response = await client.get('/services/authentication/current-context', {
      params: { output_mode: 'json' },
    });
    return response.status === 200;
  } catch {
    return false;
  }
}
