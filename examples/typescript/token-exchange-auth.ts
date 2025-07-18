/**
 * Copyright (c) 2020, 2021 Oracle and/or its affiliates.  All rights reserved.
 * This software is dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.
 */

import TokenExchangeIdentityAuthenticationDetailsProvider from "../../lib/common/lib/auth/token-exchange-identity-authentication-details-provider";
import { IdentityClient } from "../../lib/identity/lib/client";
import { Region } from "../../lib/common/lib/region";

const tokenExchangeEndpoint = process.env.OCI_TOKEN_EXCHANGE_ENDPOINT;
const thirdPartyToken = process.env.OCI_THIRD_PARTY_TOKEN;

(async () => {
  try {
    if (!tokenExchangeEndpoint || !thirdPartyToken) {
      console.error(
        "Please set the OCI_TOKEN_EXCHANGE_ENDPOINT and OCI_THIRD_PARTY_TOKEN environment variables."
      );
      return;
    }

    const provider = TokenExchangeIdentityAuthenticationDetailsProvider.builder().withRegion(Region.US_ASHBURN_1).build();
    const identityClient = new IdentityClient({ authenticationDetailsProvider: provider });
    const response = await identityClient.listRegions({});
    console.log(response.items);
  } catch (error) {
    console.error("Failed to list regions:", error);
  }
})();
