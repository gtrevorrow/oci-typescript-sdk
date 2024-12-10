/**
 * Copyright (c) 2020, 2021 Oracle and/or its affiliates.  All rights reserved.
 * This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.
 */

import UrlParser = require("url");
const httpSignature: any = require("http-signature");
import jssha = require("jssha");
import FederationClient from "./models/federation-client";
import SessionKeySupplier from "./models/session-key-supplier";
import X509CertificateSupplier from "./models/X509-certificate-supplier";
import SecurityTokenAdapter from "./security-token-adapter";
import AuthUtils from "./helpers/auth-utils";
import { RequestSigner } from "../signer";
import { HttpRequest } from "../http-request";
import { SignerRequest } from "../signer";
import { FetchHttpClient } from "../http";
import { PrivateKey } from "sshpk";
import { getStringFromRequestBody } from "../helper";
import CircuitBreaker from "../circuit-breaker";
import {
  MaxAttemptsTerminationStrategy,
  ExponentialBackoffDelayStrategyWithJitter,
  WaiterConfigurationDetails,
  WaitContextImpl,
  delay
} from "../waiter";
const Breaker = require("opossum");

/**
 * This class gets a security token from the auth service by signing the request with a PKI issued leaf certificate,
 * passing along a temporary public key that is bounded to the the security token, and the leaf certificate.
 */

const INSTANCE_PRINCIPAL_GENERIC_ERROR =
  "Instance principals authentication can only be used on OCI compute instances. Please confirm this code is running on an OCI compute instance. See https://docs.oracle.com/en-us/iaas/Content/Identity/Tasks/callingservicesfrominstances.htm for more info.";

const AUTH_TOKEN_GENERIC_ERROR = "Failed to fetch the token from auth server";

export default class X509FederationClient implements FederationClient {
  securityTokenAdapter: SecurityTokenAdapter;

  private _circuitBreaker: typeof Breaker | null = null;
  private static DEFAULT_AUTH_MAX_RETRY_COUNT = 3;
  private static DEFAULT_AUTH_MAX_DELAY_IN_SECONDS = 1;
  private static defaultAuthRetryConfiguration: WaiterConfigurationDetails = {
    terminationStrategy: new MaxAttemptsTerminationStrategy(
      X509FederationClient.DEFAULT_AUTH_MAX_RETRY_COUNT
    ),
    delayStrategy: new ExponentialBackoffDelayStrategyWithJitter(
      X509FederationClient.DEFAULT_AUTH_MAX_DELAY_IN_SECONDS
    )
  };
  httpClient: FetchHttpClient;

  constructor(
    private federationEndpoint: string,
    private _tenancyId: string,
    private _leafCertificateSupplier: X509CertificateSupplier,
    private sessionKeySupplier: SessionKeySupplier,
    private intermediateCertificateSuppliers: X509CertificateSupplier[],
    private purpose: string,
    private circuitBreaker: CircuitBreaker
  ) {
    if (this.circuitBreaker) {
      this._circuitBreaker = this.circuitBreaker.circuit;
    } else {
      this._circuitBreaker = new CircuitBreaker(CircuitBreaker.defaultAuthConfiguration).circuit;
    }
    this.securityTokenAdapter = new SecurityTokenAdapter("", this.sessionKeySupplier);
    const signer = new AuthTokenRequestSigner(this);
    this.httpClient = new FetchHttpClient(signer, this._circuitBreaker);
  }

  // Getter for tenancyId
  get tenancyId(): string {
    return this._tenancyId;
  }

  // Getter for leafCerificateSupplier
  get leafCertificateSupplier(): X509CertificateSupplier {
    return this._leafCertificateSupplier;
  }

  close() {
    if (this._circuitBreaker) {
      console.log("Shutting down the circuit breaker for the X509FederationClient");
      this._circuitBreaker.shutdown();
    }
  }

  /**
   * Gets a security token. If there is already a valid token cached, it will be returned. Else this will make a call
   * to the auth service to get a new token, using the provided suppliers.
   *
   * This method is thread-safe.
   * @return the security token
   * @throws OciError If there is any issue with getting a token from the auth server
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

      // Check if leafCertificateSupplier contains a .refresh() method. If so, call refresh()
      if (this._leafCertificateSupplier && this._leafCertificateSupplier.refresh) {
        try {
          this._leafCertificateSupplier = await this._leafCertificateSupplier.refresh();
        } catch (e) {
          throw Error(
            `Fail to refresh leafCertificateSupplier, error: ${e}. ${INSTANCE_PRINCIPAL_GENERIC_ERROR}`
          );
        }

        // When using default purpose (ex, instance principals), the token request should always be signed with the same tenant id as the certificate.
        // For other purposes, the tenant id can be different.
        if (this.purpose === "DEFAULT") {
          const newTenancyId: string = AuthUtils.getTenantIdFromCertificate(
            this._leafCertificateSupplier.getCertificateAndKeyPair().getCertificate()
          );

          if (this.tenancyId != newTenancyId) {
            throw Error("The tenancy id should never be changed in cert file!");
          }
        }
      }
      // Loop through each intermediateCertificateSuppliers and refresh them if possible
      for (let i = 0; i < this.intermediateCertificateSuppliers.length; i++) {
        try {
          if (this.intermediateCertificateSuppliers[i].refresh) {
            this.intermediateCertificateSuppliers[i] = await this.intermediateCertificateSuppliers[
              i
            ].refresh!();
          }
        } catch (e) {
          throw Error(
            "Cannot refresh the intermediate certification. " + INSTANCE_PRINCIPAL_GENERIC_ERROR
          );
        }
      }

      this.securityTokenAdapter = await this.getSecurityTokenFromServer();

      return this.securityTokenAdapter.getSecurityToken();
    }
    return this.securityTokenAdapter.getSecurityToken();
  }

  /**
   * Gets a security token from the federation server
   * @return the security token, which is basically a JWT token string
   */
  private async getSecurityTokenFromServer(): Promise<SecurityTokenAdapter> {
    let response;
    let lastKnownError;
    const waitContext = new WaitContextImpl();
    const { terminationStrategy, delayStrategy } = {
      ...X509FederationClient.defaultAuthRetryConfiguration
    };
    while (true) {
      try {
        response = await this.getTokenAsync();
        // Do not retry if the response is successful, or response status is 4XX
        if (response.status == 200) break;
        lastKnownError = `${AUTH_TOKEN_GENERIC_ERROR}. Response received but failed with status: ${response.status}`;
        console.log(lastKnownError);
        if (response.status >= 400 && response.status < 500) break;
        if (terminationStrategy.shouldTerminate(waitContext)) {
          console.log("Retry attempts exhausted! Not retrying");
          break;
        }
      } catch (e) {
        lastKnownError = `${AUTH_TOKEN_GENERIC_ERROR}. Failed with error: ${e}`;
        console.log(lastKnownError);
        if (waitContext.attemptCount < X509FederationClient.DEFAULT_AUTH_MAX_RETRY_COUNT - 1) {
          console.log(`Retrying the request...`);
        } else {
          console.log("Retry attempts exhausted! Not retrying");
          break;
        }
      }
      await delay(delayStrategy.delay(waitContext));
      waitContext.attemptCount++;
    }
    if (response !== undefined && response.status === 200) {
      const securityToken = await response.json();
      return new SecurityTokenAdapter(securityToken.token, this.sessionKeySupplier);
    }
    let error = {
      // to prevent retries on top of retries from service call
      shouldBeRetried: false,
      code: -1,
      message: lastKnownError
    };
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

    const certificateAndKeyPair = this.leafCertificateSupplier.getCertificateAndKeyPair();
    if (!certificateAndKeyPair) {
      throw Error("Certificate and key pair are not present");
    }

    const leafCertificate = certificateAndKeyPair.getCertificate();
    if (!leafCertificate) {
      throw Error("Leaf certificate is not present");
    }

    if (!certificateAndKeyPair.getPrivateKey()) {
      throw Error("Leaf certificate's private key is not present");
    }
    let intermediateStrings: string[] = [];
    if (this.intermediateCertificateSuppliers && this.intermediateCertificateSuppliers.length > 0) {
      this.intermediateCertificateSuppliers.forEach((supplier: X509CertificateSupplier) => {
        const supplierCertificateAndKeyPair = supplier.getCertificateAndKeyPair();
        if (supplierCertificateAndKeyPair && supplierCertificateAndKeyPair.getCertificate()) {
          intermediateStrings.push(
            AuthUtils.sanitizeCertificateString(
              supplierCertificateAndKeyPair.getCertificate().toString("pem")
            )
          );
        }
      });
    }

    // Create request body and call auth service.
    const url = this.federationEndpoint + "/v1/x509";
    const requestPayload = {
      certificate: AuthUtils.sanitizeCertificateString(leafCertificate.toString("pem")),
      purpose: this.purpose,
      publicKey: AuthUtils.sanitizeCertificateString(publicKey),
      intermediateCertificates: intermediateStrings
    };

    let jsonPayload = JSON.stringify(requestPayload);
    jsonPayload = jsonPayload.replace(/\\n/g, "");

    const requestObj: HttpRequest = {
      uri: url,
      body: jsonPayload,
      method: "POST",
      headers: new Headers()
    };
    const fingerprint = leafCertificate.fingerprint("sha1").toString("hex");
    const privateKey = certificateAndKeyPair.getPrivateKey() as PrivateKey;
    // Instantiate AuthTokenRequestSigner to sign the request

    // Call Auth Service to get a JSON object which contains the auth token
    const response = this.httpClient.send(requestObj);
    return response;
  }
}

// A Signer class for FederationClient
class AuthTokenRequestSigner implements RequestSigner {
  federationClient: X509FederationClient;
  constructor(federationClient: X509FederationClient) {
    this.federationClient = federationClient;
  }

  async signHttpRequest(request: HttpRequest, forceExcludeBody: boolean = false): Promise<void> {
    const tenancyId = this.federationClient.tenancyId;
    const certificateAndKeyPair = this.federationClient.leafCertificateSupplier.getCertificateAndKeyPair();
    if (!certificateAndKeyPair) {
      throw Error("Certificate and key pair are not present");
    }
    const leafCertificate = certificateAndKeyPair.getCertificate();
    const fingerprint = leafCertificate.fingerprint("sha1").toString("hex");
    const privateKey = certificateAndKeyPair.getPrivateKey() as PrivateKey;
    const apiKey = `${tenancyId}/fed-x509/${fingerprint}`;
    const headersToSign = [
      "date",
      "(request-target)",
      "host",
      "content-type",
      "content-length",
      "x-content-sha256"
    ];
    const EMPTY_SHA = "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=";

    if (!request.headers.has("host")) {
      const url = UrlParser.parse(request.uri);
      if (url.host) {
        request.headers.set("host", url.host);
      } else {
        throw new Error("Cannot parse host from url");
      }
    }

    if (!request.headers.has("x-date")) {
      request.headers.set("x-date", new Date().toUTCString());
    }

    if (!request.headers.has("Content-Type")) {
      request.headers.set("Content-Type", "application/json");
    }

    let contentLen = 0;
    const shaObj = new jssha("SHA-256", "TEXT");
    if (request.body) {
      const bodyStringContent: string = await getStringFromRequestBody(request.body);
      shaObj.update(bodyStringContent);
      request.headers.set("x-content-sha256", shaObj.getHash("B64"));
      contentLen = bodyStringContent.length;
    }

    if (contentLen === 0) {
      // if buffer is empty, it can only be an empty string payload
      request.headers.set("x-content-sha256", EMPTY_SHA);
    }

    if (!request.headers.has("Content-Length")) {
      request.headers.set("Content-Length", `${contentLen}`);
    }

    httpSignature.sign(new SignerRequest(request.method, request.uri, request.headers), {
      key: privateKey.toBuffer("pem", {}),
      keyId: apiKey,
      headers: headersToSign
    });

    const authorizationHeader = request.headers.get("authorization");
    if (authorizationHeader) {
      request.headers.set(
        "authorization",
        authorizationHeader.replace("Signature ", 'Signature version="1",')
      );
    } else {
      throw new Error("Unable to sign request");
    }
  }
}
