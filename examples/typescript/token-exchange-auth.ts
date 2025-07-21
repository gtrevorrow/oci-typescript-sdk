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
 *      .withIamDomainHost("https://identity.oraclecloud.com")
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
 * CONFIGURATION EXAMPLES:
 *
 * This example shows multiple ways to configure the token exchange authentication provider.
 * Choose the approach that best fits your deployment scenario.
 */

(async () => {
  try {
    // ================================
    // OPTION 1: Environment Variables (Recommended for CI/CD)
    // ================================
    // The builder will automatically pick up these environment variables:
    // - OCI_IAM_DOMAIN_HOST: Your tenancy's IAM Domain endpoint
    // - OCI_THIRD_PARTY_TOKEN: JWT token from your CI/CD system
    // - OCI_CLIENT_CREDENTIALS: Base64 encoded "client_id:client_secret"
    // - OCI_REGION (optional): Target OCI region

    console.log("\n=== OPTION 1: Using Environment Variables ===");
    console.log("Required environment variables:");
    console.log("- OCI_IAM_DOMAIN_HOST:", process.env.OCI_IAM_DOMAIN_HOST ? "SET" : "NOT SET");
    console.log(
      "- OCI_THIRD_PARTY_TOKEN:",
      process.env.OCI_THIRD_PARTY_TOKEN
        ? "SET (length: " + process.env.OCI_THIRD_PARTY_TOKEN.length + ")"
        : "NOT SET"
    );
    console.log(
      "- OCI_CLIENT_CREDENTIALS:",
      process.env.OCI_CLIENT_CREDENTIALS ? "SET" : "NOT SET"
    );
    console.log("- OCI_REGION (optional):", process.env.OCI_REGION || "NOT SET");

    const provider: AuthenticationDetailsProvider = TokenExchangeIdentityAuthenticationDetailsProvider.builder()
      // Override the region even if OCI_REGION is set (optional)
      .withRegion(Region.US_ASHBURN_1) // Remove this line to use OCI_REGION env var
      .build();

    // ================================
    // OPTION 2: Explicit Configuration (Alternative)
    // ================================
    // Uncomment the following section to use explicit configuration instead:
    /*
    console.log('\n=== OPTION 2: Using Explicit Builder Configuration ===');
    const provider: AuthenticationDetailsProvider = TokenExchangeIdentityAuthenticationDetailsProvider.builder()
      .withIamDomainHost("https://identity.oraclecloud.com") // Your IAM Domain endpoint
      .withThirdPartyToken("eyJ0eXAiOiJKV1QiLCJhbGc...") // Your third-party JWT token
      .withClientCredentials("Y2xpZW50X2lkOmNsaWVudF9zZWNyZXQ=") // Base64 encoded client_id:client_secret
      .withRegion(Region.US_ASHBURN_1) // Target OCI region
      .build();
    */

    // ================================
    // USING THE AUTHENTICATION PROVIDER
    // ================================

    // Create IdentityClient with the authentication provider
    // The TokenExchangeFederationClient handles auth-specific retry logic independently
    // so we don't need to configure additional retry settings here
    console.log("\n=== Creating IdentityClient and Testing Authentication ===");
    const identityClient = new IdentityClient({
      authenticationDetailsProvider: provider
    });

    // Make a test API call to verify authentication is working
    console.log("Attempting to list OCI regions...");
    const response = await identityClient.listRegions({});

    console.log("\n=== SUCCESS! Authentication and API call completed ===");
    console.log(`Found ${response.items.length} regions:`);
    response.items.forEach((region, index) => {
      console.log(`  ${index + 1}. ${region.name} (${region.key})`);
    });
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
