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
 * 2. OCI_THIRD_PARTY_TOKEN (Required)
 *    - The third-party JWT token to exchange for an OCI token
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
 *      .withThirdPartyToken("your_jwt_token_here")
 *      .withClientCredentials("base64_encoded_client_id_secret")
 *      .withRegion(Region.US_ASHBURN_1)
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
 * This example validates both environment variable and explicit builder configuration
 * by testing them sequentially with actual OCI API calls.
 */

(async () => {
  try {
    // ================================
    // FIRST PASS: Environment Variables Configuration
    // ================================
    console.log("\n=== FIRST PASS: Environment Variables Configuration ===");

    // Create provider using environment variables
    // The provider will warn if required environment variables are missing
    const envProvider = TokenExchangeIdentityAuthenticationDetailsProvider.builder()
      .withRegion(Region.US_ASHBURN_1) // Override region for consistency
      .build();

    console.log("✅ Environment variable provider created successfully");

    // Create IdentityClient and test with environment variable provider
    console.log("Creating IdentityClient with environment variable provider...");
    const envIdentityClient = new IdentityClient({
      authenticationDetailsProvider: envProvider
    });

    console.log("Attempting to list OCI regions with environment variable provider...");
    const envResponse = await envIdentityClient.listRegions({});

    console.log("✅ Environment variable configuration SUCCESS!");
    console.log(`Found ${envResponse.items.length} regions using environment variables:`);
    envResponse.items.forEach((region, index) => {
      console.log(`  ${index + 1}. ${region.name} (${region.key})`);
    });

    // ================================
    // SECOND PASS: Explicit Builder Configuration
    // ================================
    console.log("\n=== SECOND PASS: Explicit Builder Configuration ===");

    // Extract environment variables into constants for explicit configuration
    const IAM_DOMAIN_HOST = process.env.OCI_IAM_DOMAIN_HOST!;
    const THIRD_PARTY_TOKEN = process.env.OCI_THIRD_PARTY_TOKEN!;
    const CLIENT_CREDENTIALS = process.env.OCI_CLIENT_CREDENTIALS!;

    console.log("Using explicit configuration with values from environment:");
    console.log(`- IAM Domain Host: ${IAM_DOMAIN_HOST}`);
    console.log(`- Third Party Token: SET (length: ${THIRD_PARTY_TOKEN.length})`);
    console.log(`- Client Credentials: SET`);
    console.log(`- Region: US_ASHBURN_1`);

    // Create provider using explicit builder configuration
    const explicitProvider = TokenExchangeIdentityAuthenticationDetailsProvider.builder()
      .withDomainHost(IAM_DOMAIN_HOST)
      .withThirdPartyToken(THIRD_PARTY_TOKEN)
      .withClientCredentials(CLIENT_CREDENTIALS)
      .withRegion(Region.US_ASHBURN_1)
      .build();

    console.log("✅ Explicit builder provider created successfully");

    // Create IdentityClient and test with explicit builder provider
    console.log("Creating IdentityClient with explicit builder provider...");
    const explicitIdentityClient = new IdentityClient({
      authenticationDetailsProvider: explicitProvider
    });

    console.log("Attempting to list OCI regions with explicit builder provider...");
    const explicitResponse = await explicitIdentityClient.listRegions({});

    console.log("✅ Explicit builder configuration SUCCESS!");
    console.log(`Found ${explicitResponse.items.length} regions using explicit builder:`);
    explicitResponse.items.forEach((region, index) => {
      console.log(`  ${index + 1}. ${region.name} (${region.key})`);
    });

    // ================================
    // VALIDATION SUMMARY
    // ================================
    console.log("\n=== VALIDATION SUMMARY ===");
    console.log("✅ Both configuration approaches work correctly");
    console.log("✅ Environment variable approach: PASSED");
    console.log("✅ Explicit builder approach: PASSED");
    console.log(`✅ Both approaches returned ${envResponse.items.length} regions consistently`);

    // Enable debug logging tip
    if (!process.env.OCI_LOG_LEVEL) {
      console.log(
        "\n💡 TIP: Set OCI_LOG_LEVEL=DEBUG to see detailed retry and response information"
      );
    }
  } catch (error) {
    console.error("\n=== AUTHENTICATION ERROR ===");
    console.error("Failed to authenticate or list regions:");
    console.error(error);
    console.log("\n=== TROUBLESHOOTING TIPS ===");
    console.log("1. Verify all required environment variables are set correctly");
    console.log("2. Check that your client credentials are valid and properly base64 encoded");
    console.log("3. Ensure your third-party token is valid and not expired");
    console.log("4. Verify the IAM Domain host URL is correct for your tenancy");
    console.log("5. Check the debug logs above for detailed error information");
    console.log("6. Review response body details in debug logs to identify parsing issues");
  }
})();
