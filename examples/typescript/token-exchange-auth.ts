/**
 * Copyright (c) 2020, 2021 Oracle and/or its affiliates.  All rights reserved.
 * This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.
 */

/**
 * OCI Token Exchange Authentication Example
 *
 * This example demonstrates how to use token exchange authentication to authenticate
 * with OCI services using a third-party token (e.g., from GitHub Actions, AWS, Azure, etc.).
 *
 * ENVIRONMENT VARIABLES:
 * The following environment variables are required for token exchange authentication:
 *
 * 1. OCI_IAM_DOMAIN_HOST (Required)
 *    - The OCI IAM Domain host URL where token exchange will be performed
 *    - Example: "https://identity.oraclecloud.com"
 *    - This is the OCI IAM Domain endpoint for your tenancy
 *
 * 2. OCI_SUBJECT_TOKEN (Required)
 *    - The subject JWT token to exchange for an OCI token
 *    - Example: GitHub Actions provides this via ACTIONS_ID_TOKEN_REQUEST_TOKEN
 *    - AWS provides this via AWS_WEB_IDENTITY_TOKEN
 *    - Azure provides this via ACTIONS_ID_TOKEN_REQUEST_TOKEN
 *
 * 3. OCI_CLIENT_CREDENTIALS (Required)
 *    - Base64 encoded client credentials in the format "client_id:client_secret"
 *    - These are the OAuth2 client credentials configured in OCI IAM Domain
 *    - Example: echo -n "your_client_id:your_client_secret" | base64
 *
 * 4. OCI_REGION (Optional)
 *    - The OCI region to use for API calls
 *    - Example: "us-ashburn-1", "us-phoenix-1", "eu-frankfurt-1"
 *    - If not set, you must specify region in the builder or client
 *
 * BUILDER CONFIGURATION:
 * You can configure the authentication provider using the builder pattern:
 *
 * 1. Environment Variables (Automatic):
 *    TokenExchangeIdentityAuthenticationDetailsProvider.builder().build()
 *
 * 2. Explicit Configuration:
 *    TokenExchangeIdentityAuthenticationDetailsProvider.builder()
 *      .withDomainHost("https://identity.oraclecloud.com")
 *      .withSubjectToken("your_jwt_token_here")
 *      .withClientCredentials("base64_encoded_client_id_secret")
 *      .withRegion(Region.US_ASHBURN_1)
 *      .build()
 *
 * 3. Callback Provider (Fresh 3rd Party/Subject tokens on each exchange):
 *    TokenExchangeIdentityAuthenticationDetailsProvider.builder()
 *      .withSubjectToken(async () => {
 *        // Fetch fresh token from external source
 *        return await getLatestTokenFromExternalSource();
 *      })
 *      .withRegion(Region.US_ASHBURN_1)  // Other values from environment
 *      .build()
 *
 * RETRY BEHAVIOR:
 * The TokenExchangeFederationClient implements custom retry logic:
 * - 3 attempts maximum for authentication requests ( TBD make this configurable in the future )
 * - 1-second delays between attempts
 * - No retry for 4xx client errors (malformed credentials, etc.)
 * - No retry for malformed responses from the server
 * - Prevents dual retries by setting shouldBeRetried: false on final errors
 */

import { IdentityClient } from "../../lib/identity/lib/client";
import { Region } from "../../lib/common/lib/region";
import { AuthenticationDetailsProvider } from "../../lib/common";
import TokenExchangeIdentityAuthenticationDetailsProvider from "../../lib/common/lib/auth/token-exchange-identity-authentication-details-provider";
import { LOG } from "../../lib/common/lib/log";

// Configure debug logging to see retry behavior and authentication flow
const consoleLogger = {
  level: "debug",
  debug: (...args: any[]) => console.log("[DEBUG]", new Date().toISOString(), ...args),
  info: (...args: any[]) => console.log("[INFO]", new Date().toISOString(), ...args),
  warn: (...args: any[]) => console.log("[WARN]", new Date().toISOString(), ...args),
  error: (...args: any[]) => console.log("[ERROR]", new Date().toISOString(), ...args),
  trace: (...args: any[]) => console.log("[TRACE]", new Date().toISOString(), ...args)
};

// Enable debug logging for the SDK to see detailed authentication flow
LOG.logger = consoleLogger;
console.log("=== Debug logging enabled - you will see retry attempts and response details ===");

/**
 * CONFIGURATION VALIDATION:
 *
 * This example validates all three authentication configuration approaches
 * by testing them sequentially with actual OCI API calls:
 *
 * 1. Environment Variables - Uses all values from environment variables
 * 2. Explicit Builder - Sets all values explicitly via builder methods
 * 3. Callback Provider - Uses callback for third-party token, environment for others
 */

(async () => {
  // Example 1: Environment Variables (Automatic)
  console.log("[Example 1] Using environment variables:");
  console.log("OCI_IAM_DOMAIN_HOST:", process.env.OCI_IAM_DOMAIN_HOST);
  console.log("OCI_SUBJECT_TOKEN:", process.env.OCI_SUBJECT_TOKEN ? "SET" : "NOT SET");
  console.log("OCI_CLIENT_CREDENTIALS:", process.env.OCI_CLIENT_CREDENTIALS ? "SET" : "NOT SET");
  console.log("OCI_REGION:", process.env.OCI_REGION);
  const envProvider = TokenExchangeIdentityAuthenticationDetailsProvider.builder()
    .withRegion(Region.US_ASHBURN_1)
    .build();
  const envIdentityClient = new IdentityClient({ authenticationDetailsProvider: envProvider });
  const envResponse = await envIdentityClient.listRegions({});
  console.log("[Example 1] Regions:", envResponse.items.map(r => r.name).join(", "));

  // Example 2: Explicit Builder Configuration
  const IAM_DOMAIN_HOST = process.env.OCI_IAM_DOMAIN_HOST!;
  const SUBJECT_TOKEN = process.env.OCI_SUBJECT_TOKEN!;
  const CLIENT_CREDENTIALS = process.env.OCI_CLIENT_CREDENTIALS!;
  const explicitProvider = TokenExchangeIdentityAuthenticationDetailsProvider.builder()
    .withDomainHost(IAM_DOMAIN_HOST)
    .withSubjectToken(SUBJECT_TOKEN)
    .withClientCredentials(CLIENT_CREDENTIALS)
    .withRegion(Region.US_ASHBURN_1)
    .build();
  const explicitIdentityClient = new IdentityClient({
    authenticationDetailsProvider: explicitProvider
  });
  const explicitResponse = await explicitIdentityClient.listRegions({});
  console.log("[Example 2] Regions:", explicitResponse.items.map(r => r.name).join(", "));

  // Example 3: Callback Provider (Fresh tokens on each exchange)
  const subjectTokenCallback = async (): Promise<string> => {
    const token = process.env.OCI_SUBJECT_TOKEN;
    if (!token) throw new Error("OCI_SUBJECT_TOKEN environment variable is not set");
    return token;
  };
  const callbackProvider = TokenExchangeIdentityAuthenticationDetailsProvider.builder()
    .withSubjectToken(subjectTokenCallback) // Use callback for dynamic token retrieval
    .withRegion(Region.US_ASHBURN_1)
    .build();
  const callbackIdentityClient = new IdentityClient({
    authenticationDetailsProvider: callbackProvider
  });
  const callbackResponse = await callbackIdentityClient.listRegions({});
  console.log("[Example 3] Regions:", callbackResponse.items.map(r => r.name).join(", "));
})();
