// JWT Grant: no one signs in. Your server builds a small token, the JWT, that
// names your integration, the user it acts as and the scopes it needs, signs it
// with the app's RSA private key, and trades it for a one-hour access token.
// The user consents once, through the redirect URI. There is no refresh token.

import { generateKeyPairSync, sign } from "node:crypto";
import { authorizeUrl, tokenRequest } from "../shared/docusign.js";

export const JWT_SCOPE = "signature impersonation";

/** header.body.signature, Base64URL-encoded and signed RS256 with the private key. */
export function buildAssertion({ integrationKey, userId, authServer, privateKey, now = Date.now() }) {
  const header = { alg: "RS256", typ: "JWT" };
  const iat = Math.floor(now / 1000);
  const body = {
    iss: integrationKey, // your app
    sub: userId, // the user the token acts as
    aud: new URL(authServer).host, // the auth server, without https://
    iat, // issued at, from this server's clock…
    exp: iat + 3600, // …and an hour later
    scope: JWT_SCOPE,
  };
  const encode = (part) => Buffer.from(JSON.stringify(part)).toString("base64url");
  const unsigned = `${encode(header)}.${encode(body)}`;
  const signature = sign("sha256", Buffer.from(unsigned), privateKey).toString("base64url");
  return { header, body, assertion: `${unsigned}.${signature}` };
}

/** The JWT goes to the same token endpoint as every other grant. */
export const jwtTokenRequest = (authServer, assertion) =>
  tokenRequest(authServer, { grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer", assertion });

/** Individual consent, once per user. prompt=login makes Docusign ask who is signing in. */
export const consentUrl = ({ authServer, integrationKey, redirectUri }) =>
  authorizeUrl(authServer, { response_type: "code", scope: JWT_SCOPE, client_id: integrationKey, redirect_uri: redirectUri, prompt: "login" });

/**
 * Ways to break the request on purpose, one per common cause of a failed JWT
 * Grant. Each changes one input; everything else stays correct.
 */
export const JWT_BREAKS = {
  clock: {
    label: "A server clock two hours slow",
    note: "iat and exp come from a clock two hours behind, so this JWT expired an hour ago.",
    now: () => Date.now() - 2 * 3600 * 1000,
  },
  key: {
    label: "An RSA key Docusign has never seen",
    note: "Signed with a throwaway key generated just now, not the app's private key.",
    privateKey: () => generateKeyPairSync("rsa", { modulusLength: 2048 }).privateKey,
  },
  environment: {
    label: "The production endpoint",
    note: "Sent to account.docusign.com. This integration key and its RSA key only exist in the developer environment.",
    authServer: "https://account.docusign.com",
  },
};
