/**
 * Copyright (c) 2020, 2025 Oracle and/or its affiliates.  All rights reserved.
 * This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.
 */

import FederationClient from "./models/federation-client";
import SessionKeySupplier from "./models/session-key-supplier";
import SecurityTokenAdapter from "./security-token-adapter";
import { HttpRequest } from "../http-request";
import { FetchHttpClient } from "../http";
import { LOG } from "../log";
import AuthUtils from "./helpers/auth-utils";

/**
 * This class gets a security token from OCI IAM Domain token endpoint by exchanging a subject token @link{https://docs.oracle.com/en-us/iaas/Content/Identity/api-getstarted/json_web_token_exchange.htm}.
 * It uses a session key supplier to manage session keys and token validity.
 * The subject token can be provided as a string or as a callback function that returns a promise
 * resolving to the token. This allows for dynamic retrieval of the subject token, such as from
 * external sources like GitHub Actions, AWS, Azure, etc.
 * The federation client does not implement a retry policy,
 * meaning it will fail immediately on any errors during the token exchange process.
 * @class WorkloadIdentityFederationClient
 * @implements {FederationClient}
 * @constructor
 * @param {string} tokenExchangeEndpoint - The endpoint URL for the OCI IAM Domain token exchange.
 * @param {string | (() => Promise<string>)} subjectToken - The subject token to exchange for a security token.
 * @param {SessionKeySupplier} sessionKeySupplier - The supplier for session keys used to manage token validity.
 * @param {string} clientCred - The base64 encoded client ID and secret for authentication with the token exchange endpoint.
 */

const TOKEN_EXCHANGE_GENERIC_ERROR =
  "Failed to get a UPST token from OCI IAM Domain. See https://docs.oracle.com/en-us/iaas/Content/API/SDKDocs/clitoken.htm for more info.";

const AUTH_TOKEN_GENERIC_ERROR = "Failed to fetch the token from auth server";

export default class WorkloadIdentityFederationClient implements FederationClient {
  // Manages caching and validation of security tokens (JWT) with associated session keys
  private securityTokenAdapter: SecurityTokenAdapter;
  private _refreshPromise: Promise<string> | null = null;

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
    await this.getSecurityToken(); // Use getSecurityToken to handle locking
    return this.securityTokenAdapter.getStringClaim(key);
  }

  async refreshAndGetSecurityToken(): Promise<string> {
    return await this.refreshAndGetSecurityTokenInner(false);
  }

  /**
   * Refreshes the security token by making a request to the OCI IAM Domain token endpoint.
   * This method will always retrieve a new token from the federation endpoint and does not use a cached token.
   * It will also handle the session key refresh and update the security token adapter accordingly.
   * @return A promise that resolves to the new security token.
   * @throws Error If there is an issue with the token exchange process, including network errors or invalid responses.
   */
  private async refreshAndGetSecurityTokenInner(
    doFinalTokenValidityCheck: boolean
  ): Promise<string> {
    // If a refresh is already in progress, wait for it to complete.
    if (this._refreshPromise) {
      return this._refreshPromise;
    }

    // Check token validity, respecting the doFinalTokenValidityCheck flag.
    if (doFinalTokenValidityCheck && this.securityTokenAdapter.isValid()) {
      return this.securityTokenAdapter.getSecurityToken();
    }

    // Start a new refresh operation.
    this._refreshPromise = (async () => {
      try {
        this.sessionKeySupplier.refreshKeys();
        this.securityTokenAdapter = await this.getSecurityTokenFromServer();
        return this.securityTokenAdapter.getSecurityToken();
      } finally {
        // Clear the promise once the refresh is complete, allowing for future refreshes.
        this._refreshPromise = null;
      }
    })();

    return this._refreshPromise;
  }

  /**
   * Gets a security token from the OCI IAM Domain token endpoint
   * @return the security token, which is basically a JWT token string
   */
  private async getSecurityTokenFromServer(): Promise<SecurityTokenAdapter> {
    if (LOG.logger) LOG.logger.debug(`Requesting new token from server.`);
    try {
      const response = await this.getTokenAsync();

      if (response.status !== 200) {
        const errorBody = await response.text();
        if (LOG.logger)
          LOG.logger.error(
            `Token exchange request failed with status ${response.status}. Body: ${errorBody}`
          );
        throw new Error(
          `${AUTH_TOKEN_GENERIC_ERROR}. Response failed with status: ${response.status}`
        );
      }

      const responseText = await response.text();
      if (LOG.logger) LOG.logger.debug(`Received response body: ${responseText}`);

      const responseBody = JSON.parse(responseText);

      if (typeof responseBody.token !== "string" || !responseBody.token) {
        const errorMessage = `Invalid UPST token received from OCI IAM Domain. ${TOKEN_EXCHANGE_GENERIC_ERROR}`;
        if (LOG.logger) LOG.logger.error(errorMessage);
        if (LOG.logger)
          LOG.logger.debug(`Full response body: ${JSON.stringify(responseBody, null, 2)}`);
        throw new Error(errorMessage);
      }

      if (LOG.logger)
        LOG.logger.debug(
          `Successfully received and validated access token. Token length: ${responseBody.token.length}`
        );
      return new SecurityTokenAdapter(responseBody.token, this.sessionKeySupplier);
    } catch (e) {
      const finalError = new Error(
        `Failed to get security token. ${e instanceof Error ? e.message : String(e)}`
      );
      (finalError as any).cause = e;
      (finalError as any).shouldBeRetried = false;
      throw finalError;
    }
  }

  /**
   * Makes a request to the OCI IAM Domain token endpoint to exchange the subject token for a UPST token.
   * @return A promise that resolves to the HTTP response containing the UPST token.
   * @throws Error If there is an issue with the request or response.
   */
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
        requested_token_type: "urn:oci-token-type:oci-upst",
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
