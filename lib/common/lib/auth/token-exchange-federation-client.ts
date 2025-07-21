/**
 * Copyright (c) 2020, 2021 Oracle and/or its affiliates.  All rights reserved.
 * This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.
 */

import FederationClient from "./models/federation-client";
import SessionKeySupplier from "./models/session-key-supplier";
import SecurityTokenAdapter from "./security-token-adapter";
import { HttpRequest } from "../http-request";
import { FetchHttpClient } from "../http";
import { delay } from "../waiter";
import { LOG } from "../log";
import AuthUtils from "./helpers/auth-utils";

/**
 * This class gets a security token from OCI IAM Domain token endpoint by exchanging a third party token.
 *
 * RETRY STRATEGY IMPLEMENTATION:
 * This class implements custom retry logic instead of relying on the SDK's default retry mechanism
 * for the following reasons:
 *
 * 1. Auth-specific retry behavior: Authentication failures are typically non-transient
 *    (invalid credentials, permissions) and should fail fast. Our custom logic avoids
 *    retrying 4xx errors (including edge cases like 409/429 that SDK would retry).
 *
 * 2. Faster retry cycles: Uses fixed 1-second delays vs SDK's exponential backoff (up to 30s),
 *    providing quicker and more predictable feedback for transient network/server errors.
 *
 * 3. More efficient: Only retries the HTTP token request rather than recreating the
 *    entire authentication context on each attempt.
 *
 * 4. Better debugging: Clear separation between auth retries vs other SDK operation
 *    retries in logs, making authentication issues easier to diagnose.
 *
 * When using this authentication provider, configure SDK clients with NoRetryConfigurationDetails
 * to disable SDK-level retries and avoid dual retry mechanisms.
 */

const TOKEN_EXCHANGE_GENERIC_ERROR =
  "Failed to get a UPST token from OCI IAM Domain. See https://docs.oracle.com/en-us/iaas/Content/API/SDKDocs/clitoken.htm for more info.";

const AUTH_TOKEN_GENERIC_ERROR = "Failed to fetch the token from auth server";

export default class TokenExchangeFederationClient implements FederationClient {
  // Manages caching and validation of security tokens (JWT) with associated session keys
  securityTokenAdapter: SecurityTokenAdapter;

  private static DEFAULT_AUTH_MAX_RETRY_COUNT = 3; // Maximum number of retry attempts for authentication requests , make it configurable in the future
  private static DEFAULT_AUTH_MAX_DELAY_IN_SECONDS = 1; // Maximum delay in seconds between retry attempts, make it configurable in the future

  constructor(
    private tokenExchangeEndpoint: string,
    private subjectToken: string,
    private sessionKeySupplier: SessionKeySupplier,
    private clientCred: string
  ) {
    this.securityTokenAdapter = new SecurityTokenAdapter("", this.sessionKeySupplier);
  }

  /**
   * Gets a security token. If there is already a valid token cached, it will be returned. Else this will make a call
   * to the OCI IAM Domain token endpoint to get a new token, using the provided suppliers.
   *
   * This method is thread-safe.
   * @return the security token
   * @throws OciError If there is any issue with getting a token from the OCI IAM Domain token endpoint
   */
  async getSecurityToken(): Promise<string> {
    if (this.securityTokenAdapter.isValid()) {
      return this.securityTokenAdapter.getSecurityToken();
    }
    return await this.refreshAndGetSecurityTokenInner(true);
  }

  /**
   * Return a claim embedded in the security token
   * @param key the name of the claim
   * @return the value of the claim or null if unable to find
   */
  async getStringClaim(key: string): Promise<string | null> {
    await this.refreshAndGetSecurityTokenInner(true);
    return this.securityTokenAdapter.getStringClaim(key);
  }

  async refreshAndGetSecurityToken(): Promise<string> {
    return await this.refreshAndGetSecurityTokenInner(false);
  }

  private async refreshAndGetSecurityTokenInner(
    doFinalTokenValidityCheck: boolean
  ): Promise<string> {
    // Check again to see if the JWT is still invalid, unless we want to skip that check
    if (!doFinalTokenValidityCheck || !this.securityTokenAdapter.isValid()) {
      this.sessionKeySupplier.refreshKeys();

      this.securityTokenAdapter = await this.getSecurityTokenFromServer();

      return this.securityTokenAdapter.getSecurityToken();
    }
    return this.securityTokenAdapter.getSecurityToken();
  }

  /**
   * Gets a security token from the OCI IAM Domain token endpoint
   * @return the security token, which is basically a JWT token string
   */
  private async getSecurityTokenFromServer(): Promise<SecurityTokenAdapter> {
    const keyPair = this.sessionKeySupplier.getKeyPair();
    if (!keyPair) {
      throw Error("keyPair for session was not provided");
    }
    const publicKey = keyPair.getPublic();
    if (!publicKey) {
      throw Error("Public key is not present");
    }

    let response;
    let lastKnownError;
    let attemptNumber = 1;
    const maxAttempts = TokenExchangeFederationClient.DEFAULT_AUTH_MAX_RETRY_COUNT;
    const delayMs = TokenExchangeFederationClient.DEFAULT_AUTH_MAX_DELAY_IN_SECONDS * 1000;

    while (attemptNumber <= maxAttempts) {
      if (LOG.logger) LOG.logger.debug(`Token request attempt ${attemptNumber} of ${maxAttempts}`);

      try {
        response = await this.getTokenAsync();

        // Success case - try to parse the response
        if (response.status === 200) {
          let responseBody;
          let responseText;
          try {
            // First get the response as text for debugging purposes
            responseText = await response.text();
            if (LOG.logger) LOG.logger.debug(`Received response body: ${responseText}`);

            // Then parse it as JSON
            responseBody = JSON.parse(responseText);
          } catch (e) {
            lastKnownError = `Failed to read response body from OCI IAM Domain. ${TOKEN_EXCHANGE_GENERIC_ERROR}`;
            if (LOG.logger) LOG.logger.error(lastKnownError);
            if (LOG.logger && responseText) {
              LOG.logger.debug(`Failed to parse JSON response. Raw response: ${responseText}`);
            }
            // JSON parsing error - could be transient, retry
            if (attemptNumber < maxAttempts) {
              if (LOG.logger)
                LOG.logger.debug(`JSON parsing failed, retrying after ${delayMs}ms...`);
              await delay(delayMs);
              attemptNumber++;
              continue;
            } else {
              break;
            }
          }

          // Validate response body structure
          if (!responseBody) {
            lastKnownError = `Invalid (undefined) UPST token received from OCI IAM Domain. ${TOKEN_EXCHANGE_GENERIC_ERROR}`;
            if (LOG.logger) LOG.logger.error(lastKnownError);
            if (LOG.logger && responseText) {
              LOG.logger.debug(`Response body validation failed. Raw response: ${responseText}`);
            }
          } else if (typeof responseBody.token !== "string") {
            lastKnownError = `Invalid (string) UPST token received from OCI IAM Domain. ${TOKEN_EXCHANGE_GENERIC_ERROR}`;
            if (LOG.logger) LOG.logger.error(lastKnownError);
            if (LOG.logger) {
              LOG.logger.debug(
                `Response body validation failed. Expected 'token' to be string, got: ${typeof responseBody.token}`
              );
              LOG.logger.debug(`Full response body: ${JSON.stringify(responseBody, null, 2)}`);
            }
          } else {
            const token = responseBody.token;
            if (!token || token.length === 0) {
              lastKnownError = `Invalid (empty) UPST token received from OCI IAM Domain. ${TOKEN_EXCHANGE_GENERIC_ERROR}`;
              if (LOG.logger) LOG.logger.error(lastKnownError);
              if (LOG.logger) {
                LOG.logger.debug(
                  `Response body validation failed. Token is empty or null. Token length: ${
                    token ? token.length : "null"
                  }`
                );
                LOG.logger.debug(`Full response body: ${JSON.stringify(responseBody, null, 2)}`);
              }
            } else {
              // Success! Return the token
              if (LOG.logger)
                LOG.logger.debug(
                  `Successfully received and validated access token. Token length: ${token.length}`
                );
              return new SecurityTokenAdapter(token, this.sessionKeySupplier);
            }
          }

          // If we reach here, the response was malformed - don't retry these errors
          if (LOG.logger)
            LOG.logger.debug("Response validation failed - not retrying malformed response");
          break;
        }

        // Handle non-success responses
        lastKnownError = `${AUTH_TOKEN_GENERIC_ERROR}. Response received but failed with status: ${response.status}`;
        if (LOG.logger) LOG.logger.error(lastKnownError);

        // Don't retry 4xx errors (client errors)
        if (response.status >= 400 && response.status < 500) {
          if (LOG.logger) LOG.logger.debug("Client error (4xx) - not retrying");
          break;
        }
      } catch (e) {
        lastKnownError = `${AUTH_TOKEN_GENERIC_ERROR}. Failed with error: ${e}`;
        if (LOG.logger) LOG.logger.error(lastKnownError);
      }

      // Check if we should retry
      if (attemptNumber < maxAttempts) {
        if (LOG.logger) LOG.logger.debug(`Retrying after ${delayMs}ms...`);
        await delay(delayMs);
        attemptNumber++;
      } else {
        if (LOG.logger) LOG.logger.debug("Retry attempts exhausted! Not retrying");
        break;
      }
    }

    // Create a proper Error instance to prevent retries on top of retries from service call
    const error = new Error(
      lastKnownError || "Failed to get security token after all retry attempts"
    );
    (error as any).shouldBeRetried = false;
    (error as any).code = -1;
    throw error;
  }

  private async getTokenAsync(): Promise<Response> {
    const keyPair = this.sessionKeySupplier.getKeyPair();
    if (!keyPair) {
      throw Error("keyPair for session was not provided");
    }
    const publicKey = keyPair.getPublic();
    if (!publicKey) {
      throw Error("Public key is not present");
    }

    try {
      // Create request body and call auth service.
      const url = this.tokenExchangeEndpoint;
      const requestPayload = new URLSearchParams({
        grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
        requested_token_type: "urn:oci:token-type:oci-upst",
        public_key: AuthUtils.sanitizeCertificateString(publicKey),
        subject_token: this.subjectToken,
        subject_token_type: "jwt"
      }).toString();

      const headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        Authorization: `Basic ${this.clientCred}`
      };

      const requestObj: HttpRequest = {
        uri: url,
        body: requestPayload,
        method: "POST",
        headers: new Headers(headers)
      };

      const httpClient = new FetchHttpClient(null);

      // Call OCI IAM Domain token endpoint to get a base64 encoded JSON object which contains the auth token
      const response = await httpClient.send(requestObj);
      return response;
    } catch (e) {
      throw Error(`Failed to call OCI IAM Domain, error: ${e}. ${TOKEN_EXCHANGE_GENERIC_ERROR}`);
    }
  }
}
