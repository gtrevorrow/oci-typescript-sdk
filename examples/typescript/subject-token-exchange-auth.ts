/**
 * Copyright (c) 2020, 2021 Oracle and/or its affiliates.  All rights reserved.
 * This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.
 */

/**
 * OCI Subject Token Exchange Authentication Example
 *
 * This example demonstrates how to use subject token exchange authentication to authenticate
 * with OCI services using a third-party token (e.g., from GitHub Actions, AWS, Azure, etc.).
 *
 * For this example to run, you must set the following environment variables,
 * as the example code reads from them to supply values to the builder:
 * - OCI_IAM_DOMAIN_HOST
 * - OCI_SUBJECT_TOKEN
 * - OCI_CLIENT_CREDENTIALS
 *
 * BUILDER CONFIGURATION:
 * You can configure the authentication provider using the builder pattern:
 *
 * 1. Explicit Configuration:
 *    SubjectTokenExchangeIdentityAuthenticationDetailsProvider.builder()
 *      .withDomainHost("your_iam_domain_host")
 *      .withSubjectToken("your_jwt_token_here")
 *      .withClientCredentials("base64_encoded_client_id_secret")
 *      .withRegion(Region.US_ASHBURN_1)
 *      .build()
 *
 * 2. Callback Provider (Fresh Subject tokens on each exchange):
 *    SubjectTokenExchangeIdentityAuthenticationDetailsProvider.builder()
 *      .withDomainHost("your_iam_domain_host")
 *      .withClientCredentials("base64_encoded_client_id_secret")
 *      .withSubjectToken(async () => {
 *        // Fetch fresh token from external source
 *        return await getLatestTokenFromExternalSource();
 *      })
 *      .withRegion(Region.US_ASHBURN_1)
 *      .build()
 *
 * RETRY BEHAVIOR:
 * The federation client for this provider does not implement a retry policy.
 * It will fail fast on any errors during the token exchange process.
 */

import { IdentityClient } from "../../lib/identity/lib/client";
import { Region } from "oci-common/lib/region";
import { AuthenticationDetailsProvider } from "../../target/lib/common";
import SubjectTokenExchangeIdentityAuthenticationDetailsProvider from "oci-common/lib/auth/subject-token-exchange-identity-authentication-details-provider";
import { LOG } from "oci-common/lib/log";

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
 * This example validates both explicit and callback-based authentication
 * configuration approaches by testing them sequentially with actual OCI API calls:
 *
 * 1. Explicit Builder - Sets all values explicitly via builder methods
 * 2. Callback Provider - Uses callback for subject token
 */

(async () => {
  // Example 1: Explicit Builder Configuration
  const IAM_DOMAIN_HOST = process.env.OCI_IAM_DOMAIN_HOST!;
  const SUBJECT_TOKEN = process.env.OCI_SUBJECT_TOKEN!;
  const CLIENT_CREDENTIALS = process.env.OCI_CLIENT_CREDENTIALS!;

  if (!IAM_DOMAIN_HOST || !SUBJECT_TOKEN || !CLIENT_CREDENTIALS) {
    console.error(
      "Error: OCI_IAM_DOMAIN_HOST, OCI_SUBJECT_TOKEN, and OCI_CLIENT_CREDENTIALS environment variables must be set for this example."
    );
    process.exit(1);
  }

  console.log("[Example 1] Using explicit builder configuration:");
  const explicitProvider = SubjectTokenExchangeIdentityAuthenticationDetailsProvider.builder()
    .withDomainHost(IAM_DOMAIN_HOST)
    .withSubjectToken(SUBJECT_TOKEN)
    .withClientCredentials(CLIENT_CREDENTIALS)
    .withRegion(Region.US_ASHBURN_1)
    .build();
  const explicitIdentityClient = new IdentityClient({
    authenticationDetailsProvider: explicitProvider
  });
  const explicitResponse = await explicitIdentityClient.listRegions({});
  console.log("[Example 1] Regions:", explicitResponse.items.map(r => r.name).join(", "));

  // Example 2: Callback Provider (Fresh tokens on each exchange)
  console.log("\n[Example 2] Using callback provider:");
  const subjectTokenCallback = async (): Promise<string> => {
    const token = process.env.OCI_SUBJECT_TOKEN;
    if (!token) throw new Error("OCI_SUBJECT_TOKEN environment variable is not set for callback.");
    console.log("Callback invoked to fetch fresh subject token.");
    return token;
  };
  const callbackProvider = SubjectTokenExchangeIdentityAuthenticationDetailsProvider.builder()
    .withDomainHost(IAM_DOMAIN_HOST)
    .withClientCredentials(CLIENT_CREDENTIALS)
    .withSubjectToken(subjectTokenCallback) // Use callback for dynamic token retrieval
    .withRegion(Region.US_ASHBURN_1)
    .build();
  const callbackIdentityClient = new IdentityClient({
    authenticationDetailsProvider: callbackProvider
  });
  const callbackResponse = await callbackIdentityClient.listRegions({});
  console.log("[Example 2] Regions:", callbackResponse.items.map(r => r.name).join(", "));
})();
  });
  const callbackResponse = await callbackIdentityClient.listRegions({});
  console.log("[Example 2] Regions:", callbackResponse.items.map(r => r.name).join(", "));
})();
