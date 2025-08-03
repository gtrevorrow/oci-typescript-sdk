/**
 * Copyright (c) 2020, 2025 Oracle and/or its affiliates.  All rights reserved.
 * This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.
 */

import AbstractRequestingAuthenticationDetailsProvider from "./abstract-requesting-authentication-detail-provider";
import RefreshableOnNotAuthenticatedProvider from "./models/refreshable-on-not-authenticaticated-provider";
import SessionKeySupplierImpl from "./session-key-supplier";
import SessionKeySupplier from "./models/session-key-supplier";
import FederationClient from "./models/federation-client";
import WorkloadIdentityFederationClient from "./workload-identity-federation-client";
import { RegionProvider } from "./auth";
import { Region } from "../region";
/**
 * Authentication details provider for subject token exchange.
 * @link{https://docs.oracle.com/en-us/iaas/Content/Identity/api-getstarted/json_web_token_exchange.html}
 * This provider allows you to authenticate with OCI services using a subject token
 * (e.g., from GitHub Actions, AWS, Azure, etc.) and exchange it for an OCI token.
 * It supports both static and dynamic subject tokens, and can be configured using
 * the builder pattern.
 * It implements the `RegionProvider` interface to provide the region
 * and the `RefreshableOnNotAuthenticatedProvider` interface to handle token refresh
 * when the authentication fails due to an expired or invalid token.
 * This provider does not implement a retry policy; it will fail fast on any errors
 * during the token exchange process.
 * @example :
 * You can configure the authentication provider using the builder pattern:
 * 1. Explicit Configuration:
 *    WorkloadIdentityFederationAuthenticationDetailsProvider.builder()
 *      .withDomainHost("your_iam_domain_host")
 *      .withSubjectToken("your_jwt_token_here")
 *      .withClientCredentials("base64_encoded_client_id_secret")
 *      .withRegion(Region.US_ASHBURN_1)
 *      .build()
 * 2. Callback Provider (Fresh Subject tokens on each exchange):
 *    WorkloadIdentityFederationAuthenticationDetailsProvider.builder()
 *      .withDomainHost("your_iam_domain_host")
 *      .withClientCredentials("base64_encoded_client_id_secret")
 *      .withSubjectToken(async () => {
 *        // Fetch fresh token from external source
 *        return await getLatestTokenFromExternalSource();
 *      })
 *      .withRegion(Region.US_ASHBURN_1)
 *      .build();
 */
export default class WorkloadIdentityFederationAuthenticationDetailsProvider
  extends AbstractRequestingAuthenticationDetailsProvider
  implements RegionProvider, RefreshableOnNotAuthenticatedProvider<String> {
  // session key supplier
  protected _sessionKeySupplier!: SessionKeySupplier;

  // federation client
  protected _federationClient!: FederationClient;

  private _region!: Region;

  constructor(
    protected federationClient: FederationClient,
    protected sessionKeySupplier: SessionKeySupplier,
    protected region: Region
  ) {
    super(federationClient, sessionKeySupplier);
    this._federationClient = federationClient;
    this._sessionKeySupplier = sessionKeySupplier;
    this._region = region;
  }

  /**
   * Gets the region configured for this authentication provider.
   * @returns The region configured for this authentication provider.
   */
  getRegion(): Region {
    if (!this._region) {
      // Environment variable fallback removed.
      throw new Error("Region not specified. Please provide region in constructor.");
    }
    return this._region;
  }

  /**
   * Gets the session key supplier used by this authentication provider.
   * @returns The session key supplier used by this authentication provider.
   */
  async refresh(): Promise<String> {
    try {
      // Refresh the authentication token through the federation client
      const token = await this._federationClient.refreshAndGetSecurityToken();
      return token;
    } catch (error) {
      throw new Error(
        `Failed to refresh token: ${error instanceof Error ? error.message : "Unknown error"}`
      );
    }
  }

  /**
   * Gets a claim from the UPST token. This will result in a token exchange if the token is not valid.
   * @param key The name of the claim to retrieve.
   * @returns The value of the claim or null if not found.
   */

  async getClaim(key: string): Promise<string | null> {
    try {
      return await this._federationClient.getStringClaim(key);
    } catch (error) {
      throw new Error(
        `Failed to get claim '${key}': ${error instanceof Error ? error.message : "Unknown error"}`
      );
    }
  }

  /**
   * Creates a new builder for constructing instances of `TokenExchangeIdentityAuthenticationDetailsProvider`.
   *
   * @returns {WorkloadIdentityFederationAuthenticationDetailsProviderBuilder} A new builder instance.
   */
  public static builder(): WorkloadIdentityFederationAuthenticationDetailsProviderBuilder {
    return new WorkloadIdentityFederationAuthenticationDetailsProviderBuilder();
  }
}

/**
 * Builder class for constructing instances of {@link WorkloadIdentityFederationAuthenticationDetailsProvider}.
 *
 * This builder allows configuration of all required parameters for Workload Identity Federation token exchange authentication.
 *
 * The following setters are required to be called before building the provider:
 * - `withRegion(region)`
 * - `withDomainHost(domainHost)`
 * - `withSubjectToken(subjectToken)`
 * - `withClientCredentials(clientCred)`
 *
 * Usage example:
 * ```typescript
 * WorkloadIdentityFederationAuthenticationDetailsProvider.builder()
 *   .withDomainHost("identity.example.com")
 *   .withSubjectToken(async () => fetchToken())
 *   .withClientCredentials("client-credentials")
 *   .withRegion(Region.US_PHOENIX_1)
 *   .build();
 * ```
 *
 * @remarks
 * - All required parameters must be set before calling {@link build}.
 * - The subject token can be provided as a static string or a function returning a `Promise<string>`.
 * - Throws an error if any required parameter is missing when `build()` is called.
 *
 * @see {@link WorkloadIdentityFederationAuthenticationDetailsProvider}
 */
class WorkloadIdentityFederationAuthenticationDetailsProviderBuilder {
  domainHost: string | undefined;
  /**
   * The subject token to exchange for an OCI token.
   * Can be either:
   * - a string (static token)
   * - a function returning Promise<string> (dynamic provider, called each time a token is needed)
   */
  subjectToken: string | (() => Promise<string>) | undefined;
  clientCred: string | undefined;
  region!: Region;

  constructor() {}

  /**
   * Sets the region to be used by the TokenExchangeIdentityAuthenticationDetailsProvider. This is a required parameter.
   *
   * @param region - The {@link Region} to set for the authentication provider.
   * @returns The current instance of {@link WorkloadIdentityFederationAuthenticationDetailsProviderBuilder} for method chaining.
   */
  public withRegion(
    region: Region
  ): WorkloadIdentityFederationAuthenticationDetailsProviderBuilder {
    this.region = region;
    return this;
  }

  /**
   * Sets the domain host to be used for the token exchange identity authentication. This is a required parameter.
   *
   * @param domainHost - The domain host to set for the authentication provider.
   * @returns The builder instance for method chaining.
   */
  public withDomainHost(
    domainHost: string
  ): WorkloadIdentityFederationAuthenticationDetailsProviderBuilder {
    this.domainHost = domainHost;
    return this;
  }

  /**
   * Sets the subject token to be used for token exchange authentication. This is a required parameter.
   *
   * @param subjectToken - The subject token as a string or a function that returns a Promise resolving to a string.
   * @returns The builder instance for chaining.
   */
  public withSubjectToken(
    subjectToken: string | (() => Promise<string>)
  ): WorkloadIdentityFederationAuthenticationDetailsProviderBuilder {
    this.subjectToken = subjectToken;
    return this;
  }

  /**
   * Sets the client credentials to be used for token exchange authentication. This is a required parameter.
   *
   * @param clientCred - The client credentials as a string.
   * @returns The current instance of {@link WorkloadIdentityFederationAuthenticationDetailsProviderBuilder} for method chaining.
   */
  public withClientCredentials(
    clientCred: string
  ): WorkloadIdentityFederationAuthenticationDetailsProviderBuilder {
    this.clientCred = clientCred;
    return this;
  }

  /**
   * Builds and returns a new instance of {@link WorkloadIdentityFederationAuthenticationDetailsProvider}.
   *
   * This method validates that all required properties (`domainHost`, `subjectToken`, and `clientCred`)
   * have been set on the builder. If any are missing, it throws an error with a descriptive message.
   *
   * The method initializes the necessary session key supplier and federation client using the provided
   * configuration, and constructs the authentication details provider.
   *
   * @throws {Error} If `domainHost`, `subjectToken`, or `clientCred` are not set.
   * @returns {WorkloadIdentityFederationAuthenticationDetailsProvider} The configured authentication details provider.
   */
  public build(): WorkloadIdentityFederationAuthenticationDetailsProvider {
    let federationClient: FederationClient;
    let sessionKeySupplier: SessionKeySupplier;

    const domainHost = this.domainHost;

    if (!domainHost) {
      throw Error("domainHost is missing. Please use the builder's withDomainHost method.");
    }

    // Determine the subject token with proper precedence:
    // 1. Direct value from builder (string or function)
    // Environment variable fallback removed.
    const subjectToken = this.subjectToken;

    if (!subjectToken) {
      throw Error("subjectToken is missing. Please use the builder's withSubjectToken method.");
    }

    const clientCred = this.clientCred;
    if (!clientCred) {
      throw Error("clientCred is missing. Please use the builder's withClientCredentials method.");
    }

    // Initialize everything
    sessionKeySupplier = new SessionKeySupplierImpl();
    federationClient = new WorkloadIdentityFederationClient(
      `https://${domainHost}/oauth2/v1/token`,
      subjectToken,
      sessionKeySupplier,
      clientCred
    );
    return new WorkloadIdentityFederationAuthenticationDetailsProvider(
      federationClient,
      sessionKeySupplier,
      this.region
    );
  }
}
