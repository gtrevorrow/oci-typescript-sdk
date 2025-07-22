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
 * This class gets a security token from OCI IAM Domain token endpoint by exchanging a subject token.
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
 * The custom retry mechanism automatically prevents SDK-level retries by setting
 * shouldBeRetried=false on final errors, eliminating dual retry mechanisms without
 * requiring additional client configuration.
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
    private subjectToken: string | (() => Promise<string>),
    private sessionKeySupplier: SessionKeySupplier,
    private clientCred: string
  ) {
    this.securityTokenAdapter = new SecurityTokenAdapter("", this.sessionKeySupplier);
  }

  /**
   * Gets a security token. If there is already a valid token cached, it will be returned. Else this will make a call
   * to the OCI IAM Domain token endpoint to get a new token, using the provided suppliers.
   *
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
    // Check again to see if the UPST is still invalid, unless we want to skip that check
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
    let lastKnownError: any;
    const maxAttempts = TokenExchangeFederationClient.DEFAULT_AUTH_MAX_RETRY_COUNT;
    const delayMs = TokenExchangeFederationClient.DEFAULT_AUTH_MAX_DELAY_IN_SECONDS * 1000;

    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
      if (LOG.logger) LOG.logger.debug(`Token request attempt ${attempt} of ${maxAttempts}`);
      try {
        const response = await this.getTokenAsync();

        // Handle non-retriable client errors first
        if (response.status >= 400 && response.status < 500) {
          if (LOG.logger) LOG.logger.debug(`Client error (${response.status}) - not retrying`);
          lastKnownError = new Error(
            `${AUTH_TOKEN_GENERIC_ERROR}. Response failed with status: ${response.status}`
          );
          break; // Exit loop for non-retriable errors
        }

        // Handle retriable server-side errors
        if (response.status >= 500) {
          throw new Error(
            `${AUTH_TOKEN_GENERIC_ERROR}. Response failed with status: ${response.status}`
          );
        }

        // We now expect a 200 OK response. If not, treat as a retriable error.
        if (response.status !== 200) {
          throw new Error(
            `${AUTH_TOKEN_GENERIC_ERROR}. Unexpected response status: ${response.status}`
          );
        }

        // --- Success Path (status is 200) ---
        const responseText = await response.text();
        if (LOG.logger) LOG.logger.debug(`Received response body: ${responseText}`);

        const responseBody = JSON.parse(responseText); // A SyntaxError here is retriable

        if (typeof responseBody.token !== "string" || !responseBody.token) {
          // A malformed token is a non-retriable error
          lastKnownError = new Error(
            `Invalid UPST token received from OCI IAM Domain. ${TOKEN_EXCHANGE_GENERIC_ERROR}`
          );
          if (LOG.logger) LOG.logger.error(lastKnownError.message);
          if (LOG.logger)
            LOG.logger.debug(`Full response body: ${JSON.stringify(responseBody, null, 2)}`);
          break; // Exit loop
        }

        if (LOG.logger)
          LOG.logger.debug(
            `Successfully received and validated access token. Token length: ${responseBody.token.length}`
          );
        return new SecurityTokenAdapter(responseBody.token, this.sessionKeySupplier);
      } catch (e) {
        // This block catches network errors, 5xx errors, and JSON parsing errors.
        // All of these are considered retriable.
        lastKnownError = e;
        if (LOG.logger) {
          const errorMessage = e instanceof Error ? e.message : String(e);
          LOG.logger.error(
            `${AUTH_TOKEN_GENERIC_ERROR}. Encountered retriable error: ${errorMessage}`
          );
        }
      }

      // If we're here, a retriable error occurred. Wait before the next attempt.
      if (attempt < maxAttempts) {
        if (LOG.logger) LOG.logger.debug(`Retrying after ${delayMs}ms...`);
        await delay(delayMs);
      }
    }

    // If the loop completes, all attempts have failed.
    const finalError = new Error(
      lastKnownError?.message || "Failed to get security token after all retry attempts"
    );
    // Preserve the original error as the cause for better debugging
    if (lastKnownError) (finalError as any).cause = lastKnownError;
    (finalError as any).shouldBeRetried = false;
    (finalError as any).code = -1;
    throw finalError;
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

      // Resolve the subject token (token being exchanged for UPST):
      // - If subjectToken is a callback, invoke it to get fresh token each time
      // - If subjectToken is a string, use it directly
      let resolvedSubjectToken: string;

      if (typeof this.subjectToken === "function") {
        // Callback has highest precedence - invoke it to get fresh token
        try {
          resolvedSubjectToken = await this.subjectToken();
        } catch (error) {
          throw new Error(
            `Failed to get subject token from callback: ${
              error instanceof Error ? error.message : "Unknown error"
            }`
          );
        }
      } else {
        // Use the provided string token (this already includes the precedence logic from the builder)
        resolvedSubjectToken = this.subjectToken;
      }

      if (!resolvedSubjectToken) {
        throw new Error("Resolved subject token is empty or null");
      }

      const requestPayload = new URLSearchParams({
        grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
        requested_token_type: "urn:oci:token-type:oci-upst",
        public_key: AuthUtils.sanitizeCertificateString(publicKey),
        subject_token: resolvedSubjectToken,
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
