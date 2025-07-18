/**
 * Copyright (c) 2020, 2021 Oracle and/or its affiliates.  All rights reserved.
 * This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.
 */

import TokenExchangeIdentityAuthenticationDetailsProvider from "../../lib/common/lib/auth/token-exchange-identity-authentication-details-provider";
import { IdentityClient } from "../../lib/identity/lib/client";
import { Region } from "../../lib/common/lib/region";
import { AuthenticationDetailsProvider } from "../../lib/common";


(async () => {
  try {
    // The builder will automatically pick up the required environment variables:
    // OCI_IAM_DOMAIN_HOST, OCI_THIRD_PARTY_TOKEN, OCI_CLIENT_CREDENTIALS
    // You can also set OCI_REGION, or specify the region in the builder.
    const provider: AuthenticationDetailsProvider = TokenExchangeIdentityAuthenticationDetailsProvider.builder()
      .withRegion(Region.US_ASHBURN_1) // Remove this line to use OCI_REGION env var
      .build();

    const identityClient = new IdentityClient({ authenticationDetailsProvider: provider });
    const response = await identityClient.listRegions({});
    console.log(response.items);
  } catch (error) {
    console.error("Failed to list regions:", error);
  }
})();
