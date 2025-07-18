/**
 * Copyright (c) 2020, 2021 Oracle and/or its affiliates.  All rights reserved.
 * This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.
 */

import AbstractRequestingAuthenticationDetailsProvider from "./abstract-requesting-authentication-detail-provider";
import RefreshableOnNotAuthenticatedProvider from "./models/refreshable-on-not-authenticaticated-provider";
import SessionKeySupplierImpl from "./session-key-supplier";
import SessionKeySupplier from "./models/session-key-supplier";
import FederationClient from "./models/federation-client";
import TokenExchangeFederationClient from "./token-exchange-federation-client";
import { RegionProvider } from "./auth";
import { Region } from "../region";


export default class TokenExchangeIdentityAuthenticationDetailsProvider extends AbstractRequestingAuthenticationDetailsProvider
    implements RegionProvider, RefreshableOnNotAuthenticatedProvider<String> {

    // Environment variable names
    public static readonly IAM_DOMAIN_HOST_ENV_VAR_NAME = "OCI_IAM_DOMAIN_HOST";
    public static readonly THIRD_PARTY_TOKEN_ENV_VAR_NAME = "OCI_THIRD_PARTY_TOKEN";

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
            // Try to get region from environment variable
            const regionString = process.env.OCI_REGION;
            if (regionString) {
                this._region = Region.fromRegionId(regionString);
            } else {
                throw new Error("Region not specified. Set OCI_REGION environment variable or provide region in constructor.");
            }
        }
        return this._region;
    }

    async refresh(): Promise<String> {
        try {
            // Refresh the authentication token through the federation client
            const token = await this._federationClient.refreshAndGetSecurityToken();
            return token;
        } catch (error) {
            throw new Error(`Failed to refresh token: ${error instanceof Error ? error.message : 'Unknown error'}`);
        }
    }

    // Builder method to create OkeWorkloadIdentityAuthenticationDetailsProviderBuilder which will build
    // OkeWorkloadIdentityAuthenticationDetailsProvider
    public static builder(): TokenExchangeIdentityAuthenticationDetailsProviderBuilder {
        return new TokenExchangeIdentityAuthenticationDetailsProviderBuilder();
    }


    }
    
    class TokenExchangeIdentityAuthenticationDetailsProviderBuilder {
         domainHost: string | undefined;
         thirdPartyToken: string | undefined;
         clientCred: string | undefined;
         region!: Region;

        constructor(
        ) { }

        public withRegion(region: Region): TokenExchangeIdentityAuthenticationDetailsProviderBuilder {
            this.region = region;
            return this;
        }

        public withDomainHost(domainHost: string): TokenExchangeIdentityAuthenticationDetailsProviderBuilder {
            this.domainHost = domainHost;
            return this;
        }

        public withThirdPartyToken(thirdPartyToken: string): TokenExchangeIdentityAuthenticationDetailsProviderBuilder {
            this.thirdPartyToken = thirdPartyToken;
            return this;
        }

        public withClientCredentials(clientCred: string): TokenExchangeIdentityAuthenticationDetailsProviderBuilder {
            this.clientCred = clientCred;
            return this;
        }

        public build(): TokenExchangeIdentityAuthenticationDetailsProvider {
            let federationClient: FederationClient;
            let sessionKeySupplier: SessionKeySupplier;

            const domainHost =
                this.domainHost ||
                process.env[
                TokenExchangeIdentityAuthenticationDetailsProvider.IAM_DOMAIN_HOST_ENV_VAR_NAME
                ];

            if (!domainHost) {
                throw Error(
                    `${TokenExchangeIdentityAuthenticationDetailsProvider.IAM_DOMAIN_HOST_ENV_VAR_NAME} is missing. Please set it in the environment variables or use the builder's withDomainHost method.`
                );
            }
            // Get the third party token from environment variable
            // This token is expected to be a JWT or similar format that can be exchanged for an
            // OCI IAM Domain token.
            const thirdPartyToken =
                this.thirdPartyToken ||
                process.env[
                TokenExchangeIdentityAuthenticationDetailsProvider.THIRD_PARTY_TOKEN_ENV_VAR_NAME
                ];
            if (!thirdPartyToken) {
                throw Error(
                    `${TokenExchangeIdentityAuthenticationDetailsProvider.THIRD_PARTY_TOKEN_ENV_VAR_NAME} is missing. Please set it in the environment variables or use the builder's withThirdPartyToken method.`
                );
            }

            const clientCred = this.clientCred || process.env.OCI_CLIENT_CREDENTIALS;
            if (!clientCred) {
                throw Error(
                    "OCI_CLIENT_CREDENTIALS is missing. Please set it in the environment variables or use the builder's withClientCredentials method."
                );
            }

            // Initialize everything
            sessionKeySupplier = new SessionKeySupplierImpl();
            federationClient = new TokenExchangeFederationClient(
                `https://${domainHost}/oauth2/v1/token`,
                thirdPartyToken,
                sessionKeySupplier,
                clientCred
            );
            return new TokenExchangeIdentityAuthenticationDetailsProvider(
                federationClient,
                sessionKeySupplier,
                this.region
            );
        }

    }




