// Public Authorization Code Grant with PKCE, entirely in the browser.
//
// A browser can't keep a secret: anything shipped to it can be read. So before
// each sign-in this page makes a random code verifier and sends Docusign only
// its SHA-256 hash, the code challenge. When the code comes back, the page
// sends the verifier with it. Docusign hashes the verifier, compares, and only
// issues a token if they match. A stolen code is useless without the verifier.
//
// The token request and /oauth/userinfo go straight from this page to Docusign,
// which is why the app needs CORS: an origin URL and Allow CORS for OAuth calls.

import { authorizeUrl, send, tokenFacts, tokenRequest, useToken } from "/shared/docusign.js";
import { countdown, esc, explain, facts, field, readonly, setMasking, stepsHtml } from "/shared/view.js";

const CONFIG = JSON.parse(document.getElementById("pkce-config").textContent);
setMasking(CONFIG.maskIds);

/* ── 1 · the code verifier: a long random string, new for every sign-in ── */

const base64url = (bytes) => btoa(String.fromCharCode(...bytes)).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");

// 64 random bytes make 86 characters. PKCE allows 43 to 128.
const newVerifier = () => base64url(crypto.getRandomValues(new Uint8Array(64)));

/* ── 2 · the code challenge: SHA-256 of the verifier, Base64URL-encoded ─── */

async function challengeFor(verifier) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
  return base64url(new Uint8Array(digest));
}

/* ── 3 · sign in, sending the challenge. The verifier stays here. ──────── */

const signInUrl = ({ challenge, state }) =>
  authorizeUrl(CONFIG.authServer, {
    response_type: "code",
    scope: "signature cors", // cors: this page may call Docusign directly
    client_id: CONFIG.integrationKey,
    redirect_uri: CONFIG.redirectUri,
    code_challenge: challenge,
    code_challenge_method: "S256",
    state,
    prompt: "login",
  });

/* ── 4 · the code and the verifier for tokens. No secret. ───────────────── */

const exchangeRequest = (code, verifier) =>
  tokenRequest(CONFIG.authServer, { grant_type: "authorization_code", code, client_id: CONFIG.integrationKey, code_verifier: verifier });

const refreshRequest = (refreshToken) =>
  tokenRequest(CONFIG.authServer, { grant_type: "refresh_token", refresh_token: refreshToken, client_id: CONFIG.integrationKey });

/** The browser adds Origin to every cross-origin request; the page can't set or remove it. */
const fromBrowser = (request) => ({ ...request, implicitHeaders: { Origin: `${location.origin}  (added by the browser)` } });

/* ── the page ───────────────────────────────────────────────────────────── */

// The verifier has to survive the round trip to Docusign's sign-in page.
const SAVED = "pkce-sign-in";
const steps = [];
let actions = "";
let signIn = {}; // { verifier, challenge, state, url }
let code = "";
let tokens = null;

const button = (action, label, kind = "primary") => `<button type="button" class="btn ${kind}" data-action="${action}">${esc(label)}</button>`;
const value = (label, text, note) => field(label, readonly(text), esc(note));

function render() {
  document.getElementById("steps").innerHTML = stepsHtml(steps);
  document.getElementById("actions").innerHTML = actions;
}

const verifierStep = () => ({
  title: "Generate the code verifier",
  state: "done",
  lead: "A long random string, made fresh for every sign-in. It stays on this page until the token request.",
  html: value("code_verifier", signIn.verifier, `${signIn.verifier.length} random characters`),
});

const challengeStep = () => ({
  title: "Hash it into the code challenge",
  state: "done",
  lead: "SHA-256 of the verifier, then Base64URL. Only this hash goes to Docusign with the sign-in.",
  html: value("code_challenge", signIn.challenge, "code_challenge_method=S256"),
});

const signInStep = () => ({ title: "Send the user to Docusign with the challenge", state: "done", request: { method: "GET", url: signIn.url } });

function start() {
  sessionStorage.removeItem(SAVED);
  signIn = {};
  tokens = null;
  steps.length = 0;
  steps.push({
    title: "Generate the code verifier",
    state: "next",
    lead: "A long random string, made fresh for every sign-in. It stays on this page until the token request.",
  });
  actions = button("generate", "Generate the code verifier");
  history.replaceState(null, "", "/pkce");
  render();
}

const ACTIONS = {
  start,

  generate() {
    signIn.verifier = newVerifier();
    steps[0] = verifierStep();
    steps.push({
      title: "Hash it into the code challenge",
      state: "next",
      lead: "SHA-256 of the verifier, then Base64URL. Only this hash goes to Docusign with the sign-in.",
    });
    actions = button("hash", "Hash it: SHA-256, then Base64URL");
  },

  async hash() {
    signIn.challenge = await challengeFor(signIn.verifier);
    signIn.state = base64url(crypto.getRandomValues(new Uint8Array(16)));
    signIn.url = signInUrl(signIn);
    steps[1] = challengeStep();
    steps.push({ ...signInStep(), state: "next" });
    actions = button("go", "Sign in with Docusign");
  },

  go() {
    sessionStorage.setItem(SAVED, JSON.stringify(signIn));
    location.assign(signIn.url);
  },

  exchange: () => exchange("right"),
  "wrong-verifier": () => exchange("wrong-verifier"),
  "no-origin": () => exchange("no-origin"),

  async refresh() {
    const request = fromBrowser(refreshRequest(tokens.refresh_token));
    const result = await send(request);
    if (result.ok) tokens = result.body;
    steps.push({
      title: "Refresh the access token",
      state: result.ok ? "done" : "error",
      request,
      response: result,
      hint: result.ok ? "" : explain(result),
      html: result.ok ? tokenFacts(result.body, REFRESH) : "",
    });
  },
};

const REFRESH = {
  refresh: "yes · 24 hours for a single-page app, and it can't be extended",
  renewBefore: { label: "Refresh by (30 minutes early)", seconds: 30 * 60 },
};

async function exchange(kind) {
  const titles = {
    right: "Exchange the code and the verifier. No secret.",
    "wrong-verifier": "Exchange the code with a different verifier",
    "no-origin": "Exchange the code from a server, without an Origin header",
  };
  let request, result;
  if (kind === "no-origin") {
    // The same request, sent by server.js: no browser, so no Origin header.
    request = { ...exchangeRequest(code, signIn.verifier), implicitHeaders: { Origin: "(none: sent from a server)" } };
    result = await fetch("/pkce/no-origin", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(request.form) })
      .then((r) => r.json())
      .catch((err) => ({ ok: false, status: 0, body: { error: "no_response", error_description: err.message } }));
  } else {
    request = fromBrowser(exchangeRequest(code, kind === "right" ? signIn.verifier : newVerifier()));
    result = await send(request);
  }

  if (!result.ok) {
    steps.push({ title: titles[kind], state: "error", request, response: result, hint: explain(result) });
    actions = `${button("exchange", "Exchange with the right verifier")}${button("start", "Start over", "quiet")}${button("no-origin", "Send it from a server, no Origin", "break")}`;
    return;
  }

  tokens = result.body;
  steps[3] = { ...steps[3], state: "done", html: facts([["Code", "used: a code works once"]]) };
  steps.push({ title: titles[kind], state: "done", request, response: result, html: tokenFacts(tokens, REFRESH) });
  sessionStorage.removeItem(SAVED); // the verifier is spent
  history.replaceState(null, "", "/pkce");
  render();
  await useToken(steps, CONFIG.authServer, tokens.access_token);
  actions = `${button("refresh", "Refresh the token")}${button("start", "Start over", "quiet")}`;
}

/** Docusign sent the browser back to the redirect URI: ?code=…&state=…, or ?error=… */
function returned(params) {
  signIn = JSON.parse(sessionStorage.getItem(SAVED) ?? "{}");
  if (!signIn.verifier) {
    steps.push({ title: "Back from Docusign", state: "error", lead: "This page has no code verifier for that sign-in. Start over." });
    actions = button("start", "Start over");
    return render();
  }
  steps.push(verifierStep(), challengeStep(), signInStep());
  const redirect = { method: "GET", url: location.href };

  if (params.get("error") || params.get("state") !== signIn.state) {
    const body = params.get("error")
      ? { error: params.get("error"), error_description: params.get("error_description") ?? "" }
      : { error: "state_mismatch", error_description: "This redirect doesn't belong to the sign-in this page started." };
    steps.push({ title: "Back at the redirect URI", state: "error", error: body.error, request: redirect, hint: explain({ status: 400, body }) || body.error_description });
    actions = button("start", "Start over");
    return render();
  }

  code = params.get("code");
  steps.push({
    title: "Back at the redirect URI with an authorization code",
    state: "next",
    request: redirect,
    lead: "Only this page can use the code: the token request needs the verifier, and the verifier never left the page.",
    html: facts([["Code valid for", { html: countdown(Date.now() + 120 * 1000) }]]),
  });
  actions = [
    button("exchange", "Exchange the code and the verifier"),
    `<span class="break-label">Break it:</span>`,
    button("wrong-verifier", "a different verifier", "break"),
    button("no-origin", "from a server, no Origin", "break"),
  ].join("");
  render();
}

document.getElementById("actions").addEventListener("click", async (event) => {
  const action = event.target.closest("[data-action]")?.dataset.action;
  if (!action) return;
  for (const b of document.querySelectorAll("#actions button")) b.disabled = true;
  await ACTIONS[action]();
  render();
});

if (!CONFIG.integrationKey) {
  steps.push({
    title: "Add the public app's integration key",
    state: "next",
    lead: "Set <code>DOCUSIGN_PUBLIC_INTEGRATION_KEY</code> in <code>.env</code> to the integration key of the app you set to <b>No</b>, it can't store a secret. Then restart the server.",
  });
  render();
} else {
  const params = new URLSearchParams(location.search);
  if (params.has("code") || params.has("error")) returned(params);
  else start();
}
