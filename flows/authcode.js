// Confidential Authorization Code Grant: a person signs in. Your server sends
// them to Docusign, gets an authorization code back on the redirect URI, and
// exchanges it, with the integration key and the secret key, for an access
// token and a refresh token. The secret key never leaves the server.

import { authorizeUrl, tokenRequest } from "../shared/docusign.js";

/** Where the browser goes to sign in. `state` ties the answer to this sign-in. */
export const signInUrl = ({ authServer, integrationKey, redirectUri, state, extended }) =>
  authorizeUrl(authServer, {
    response_type: "code",
    // extended: each refresh renews the refresh token's full lifetime
    scope: extended ? "signature extended" : "signature",
    client_id: integrationKey,
    redirect_uri: redirectUri,
    state,
    prompt: "login",
  });

/** The integration key and secret key, as HTTP Basic authentication. */
const basic = (integrationKey, secretKey) => ({
  Authorization: `Basic ${Buffer.from(`${integrationKey}:${secretKey}`).toString("base64")}`,
});

/** Within two minutes of the redirect: the code for tokens. */
export const codeExchangeRequest = ({ authServer, integrationKey, secretKey, code }) =>
  tokenRequest(authServer, { grant_type: "authorization_code", code }, basic(integrationKey, secretKey));

/** A new access token, and a new refresh token, without another sign-in. */
export const refreshRequest = ({ authServer, integrationKey, secretKey, refreshToken }) =>
  tokenRequest(authServer, { grant_type: "refresh_token", refresh_token: refreshToken }, basic(integrationKey, secretKey));
