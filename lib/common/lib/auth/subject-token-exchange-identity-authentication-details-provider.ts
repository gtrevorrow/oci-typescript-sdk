/**
 * Copyright (c) 2020, 2021 Oracle and/or its affiliates.  All rights reserved.
 * This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.
 */

import AbstractRequestingAuthenticationDetailsProvider from "./abstract-requesting-authentication-detail-provider";
import RefreshableOnNotAuthenticatedProvider from "./models/refreshable-on-not-authenticaticated-provider";
import SessionKeySupplierImpl from "./session-key-supplier";
import SessionKeySupplier from "./models/session-key-supplier";
import FederationClient from "./models/federation-client";
import SubjectTokenExchangeFederationClient from "./subject-token-exchange-federation-client";
import { RegionProvider } from "./auth";
import { Region } from "../region";

export default class SubjectTokenExchangeIdentityAuthenticationDetailsProvider
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

  getRegion(): Region {
    if (!this._region) {
      // Environment variable fallback removed.
      throw new Error("Region not specified. Please provide region in constructor.");
    }
    return this._region;
  }

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

  public static builder(): TokenExchangeIdentityAuthenticationDetailsProviderBuilder {
    return new TokenExchangeIdentityAuthenticationDetailsProviderBuilder();
  }
}

class TokenExchangeIdentityAuthenticationDetailsProviderBuilder {
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

  public withRegion(region: Region): TokenExchangeIdentityAuthenticationDetailsProviderBuilder {
    this.region = region;
    return this;
  }

  public withDomainHost(
    domainHost: string
  ): TokenExchangeIdentityAuthenticationDetailsProviderBuilder {
    this.domainHost = domainHost;
    return this;
  }

  /**
   * Sets the subject token to exchange for an OCI token.
   * @param subjectToken - Either a string (static token) or a function returning Promise<string> (dynamic provider).
   */
  public withSubjectToken(
    subjectToken: string | (() => Promise<string>)
  ): TokenExchangeIdentityAuthenticationDetailsProviderBuilder {
    this.subjectToken = subjectToken;
    return this;
  }

  public withClientCredentials(
    clientCred: string
  ): TokenExchangeIdentityAuthenticationDetailsProviderBuilder {
    this.clientCred = clientCred;
    return this;
  }

  public build(): SubjectTokenExchangeIdentityAuthenticationDetailsProvider {
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
      throw Error(
        "subjectToken is missing. Please use the builder's withSubjectToken method."
      );
    }

    const clientCred = this.clientCred;
    if (!clientCred) {
      throw Error(
        "clientCred is missing. Please use the builder's withClientCredentials method."
      );
    }

    // Initialize everything
    sessionKeySupplier = new SessionKeySupplierImpl();
    federationClient = new SubjectTokenExchangeFederationClient(
      `https://${domainHost}/oauth2/v1/token`,
      subjectToken,
      sessionKeySupplier,
      clientCred
    );
    return new SubjectTokenExchangeIdentityAuthenticationDetailsProvider(
      federationClient,
      sessionKeySupplier,
      this.region
    );
  }
}
