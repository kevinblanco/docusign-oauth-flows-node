// The Docusign calls every flow shares. Plain fetch, so this file runs in Node
// (server.js) and in the browser (the PKCE page) unchanged.
//
// A request is described as data, { method, url, headers, form }, and the same
// object is sent and shown on the page, so what you see is what went out.

import { clock, duration, explain, facts, mask } from "./view.js";

/** /oauth/auth with these query parameters. Spaces encode as %20, the way Docusign's docs write scopes. */
export function authorizeUrl(authServer, params) {
  const query = Object.entries(params)
    .filter(([, v]) => v != null && v !== "")
    .map(([k, v]) => `${k}=${encodeURIComponent(v)}`)
    .join("&");
  return `${authServer}/oauth/auth?${query}`;
}

/** POST /oauth/token. Every grant uses it; only the form fields change. */
export const tokenRequest = (authServer, form, headers = {}) => ({ method: "POST", url: `${authServer}/oauth/token`, headers, form });

/** Who signed in, their accounts, and each account's base URI. */
export const userinfoRequest = (authServer, accessToken) => ({
  method: "GET",
  url: `${authServer}/oauth/userinfo`,
  headers: { Authorization: `Bearer ${accessToken}` },
});

/** One eSignature REST API call to prove the token works: envelopes changed in the last 30 days. */
export function envelopesRequest(baseUri, accountId, accessToken) {
  const since = new Date(Date.now() - 30 * 864e5).toISOString().slice(0, 10);
  return {
    method: "GET",
    url: `${baseUri}/restapi/v2.1/accounts/${accountId}/envelopes?from_date=${since}&count=1`,
    headers: { Authorization: `Bearer ${accessToken}` },
  };
}

/** Sends a request description. Resolves { ok, status, body }: OAuth errors are answers, not exceptions. */
export async function send({ method, url, headers = {}, form }) {
  try {
    const res = await fetch(url, {
      method,
      headers: form ? { ...headers, "Content-Type": "application/x-www-form-urlencoded" } : headers,
      body: form ? new URLSearchParams(form) : undefined,
    });
    const text = await res.text();
    let body;
    try {
      body = text ? JSON.parse(text) : {};
    } catch {
      body = { text }; // an HTML error page
    }
    return { ok: res.ok, status: res.status, body };
  } catch (err) {
    // In a browser, a CORS rejection lands here: the page never sees a status.
    return { ok: false, status: 0, body: { error: "no_response", error_description: err.message } };
  }
}

/**
 * What matters about a token in each flow: how long it lasts, what replaces it,
 * and when to get the next one. `refresh` describes the flow's refresh token.
 */
export function tokenFacts(token, { refresh, renewBefore }) {
  const expiresAt = Date.now() + token.expires_in * 1000;
  return facts([
    ["Access token lifetime", `${duration(token.expires_in)} (expires_in ${token.expires_in})`],
    ["Refresh token", refresh],
    [renewBefore.label, clock(expiresAt - renewBefore.seconds * 1000)],
  ]);
}

/**
 * After any flow: find the account with /oauth/userinfo, then make one API call
 * with the token. Appends the two steps to `steps`.
 */
export async function useToken(steps, authServer, accessToken) {
  const infoRequest = userinfoRequest(authServer, accessToken);
  const info = await send(infoRequest);
  if (!info.ok) {
    steps.push({ title: "Find the account and its base URI", state: "error", request: infoRequest, response: info, hint: explain(info) });
    return;
  }
  const account = info.body.accounts.find((a) => a.is_default) ?? info.body.accounts[0];
  steps.push({
    title: "Find the account and its base URI",
    state: "done",
    request: infoRequest,
    response: { ...info, show: ["sub", "name", "accounts"] },
    html: facts([
      ["User ID (sub)", mask.ids(info.body.sub)],
      ["Account", account.account_name],
      ["Base URI", account.base_uri],
    ]),
  });

  const callRequest = envelopesRequest(account.base_uri, account.account_id, accessToken);
  const call = await send(callRequest);
  steps.push({
    title: "Use the token: one eSignature REST API call",
    state: call.ok ? "done" : "error",
    request: callRequest,
    response: call.ok ? { ...call, show: ["resultSetSize", "totalSetSize"] } : call,
    hint: call.ok ? "" : explain(call),
  });
}
