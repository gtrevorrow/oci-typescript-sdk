/**
 * Copyright (c) 2020, 2021 Oracle and/or its affiliates.  All rights reserved.
 * This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.
 */

import FederationClient from "./models/federation-client";
import SessionKeySupplier from "./models/session-key-supplier";
import SecurityTokenAdapter from "./security-token-adapter";
import { HttpRequest } from "../http-request";
import { FetchHttpClient } from "../http";

/**
 * This class gets a security token from OCI IAM Domain token endpoint by exchanging a third party token.
 */

const TOKEN_EXCHANGE_GENERIC_ERROR =
  "Failed to get a UPST token from OCI IAM Domain. See https://docs.oracle.com/en-us/iaas/Content/API/SDKDocs/clitoken.htm for more info.";

export default class TokenExchangeFederationClient implements FederationClient {
  securityTokenAdapter: SecurityTokenAdapter;
  private retry = 0;

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

    try {
      // Create request body and call auth service.
      const url = this.tokenExchangeEndpoint;
      const requestPayload = {
        grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
        requested_token_type: "urn:oci:token-type:oci-upst",
        public_key: this.sessionKeySupplier.getKeyPair().getPublic().toString(),
        subject_token: this.subjectToken,
        subject_token_type: "jwt",
      };

      const headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        Authorization: `Basic ${this.clientCred}`,
      };

      let jsonPayload = JSON.stringify(requestPayload);
      jsonPayload = jsonPayload.replace(/\n/g, "");

      const requestObj: HttpRequest = {
        uri: url,
        body: jsonPayload,
        method: "POST",
        headers: new Headers(headers)
      };

      const httpClient = new FetchHttpClient(null);

      // Call OCI IAM Domain token endpoint to get a base64 encoded JSON object which contains the auth token
      const response = await httpClient.send(requestObj);
      //TODO: Implement retry here
      // retry here
      if (response.status !== 200) {
        if (this.retry < 3) {
          this.retry += 1;
          return await this.getSecurityTokenFromServer();
        } else {
          throw Error(
            `Failed to call OCI IAM Domain for UPST token. Status: ${response.status}. ${TOKEN_EXCHANGE_GENERIC_ERROR}`
          );
        }
      }
      this.retry = 0;

      let responseBody;
      try {
        responseBody = await response.json();
      } catch (e) {
        throw Error(
          `Failed to read response body from OCI IAM Domain. ${TOKEN_EXCHANGE_GENERIC_ERROR}`
        );
      }

      if (!responseBody) {
        throw Error(
          `Invalid (undefined) UPST token received from OCI IAM Domain. ${TOKEN_EXCHANGE_GENERIC_ERROR}`
        );
      }
      if (typeof responseBody.access_token !== "string") {
        throw Error(
          `Invalid (string) UPST token received from OCI IAM Domain. ${TOKEN_EXCHANGE_GENERIC_ERROR}`
        );
      }

      const token = responseBody.access_token;
      if (!token || token.length === 0) {
        throw Error(
          `Invalid (empty) UPST token received from OCI IAM Domain. ${TOKEN_EXCHANGE_GENERIC_ERROR}`
        );
      }

      return new SecurityTokenAdapter(token, this.sessionKeySupplier);
    } catch (e) {
      throw Error(`Failed to call OCI IAM Domain, error: ${e}. ${TOKEN_EXCHANGE_GENERIC_ERROR}`);
    }
  }
}