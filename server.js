#!/usr/bin/env node
// Docusign OAuth, three ways: one local app that runs each flow from the
// tutorial and shows every request and response, with IDs and tokens masked.
//
//   /jwt      JWT Grant                               on the server   flows/jwt.js
//   /acg      Confidential Authorization Code Grant   on the server   flows/authcode.js
//   /pkce     Public Authorization Code Grant + PKCE  in the browser  public/pkce.js
//   /errors   the five errors from the tutorial, and how to cause each one here
//
// No SDK, no dependencies: Node.js 20.12+ with its built-in fetch and crypto.
// Setup: copy .env.example to .env and fill it in. See README.md.

import { createPrivateKey, randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { createServer } from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { codeExchangeRequest, refreshRequest, signInUrl } from "./flows/authcode.js";
import { buildAssertion, consentUrl, JWT_BREAKS, jwtTokenRequest } from "./flows/jwt.js";
import { authorizeUrl, send, tokenFacts, tokenRequest, useToken } from "./shared/docusign.js";
import { banner, clock, countdown, esc, explain, facts, field, icon, mask, readonly, setMasking, stepsHtml } from "./shared/view.js";

const HERE = path.dirname(fileURLToPath(import.meta.url));
try {
  process.loadEnvFile(path.join(HERE, ".env"));
} catch {
  // no .env file: read the settings from the environment instead
}

/* ── settings ────────────────────────────────────────────────────────────── */

const env = (name, fallback = "") => process.env[name]?.trim() || fallback;

const CONFIG = {
  appUrl: env("APP_URL", "http://localhost:3000").replace(/\/$/, ""),
  // developer accounts authenticate at account-d.docusign.com; production at account.docusign.com
  authServer: env("DOCUSIGN_AUTH_SERVER", "https://account-d.docusign.com"),
  // The confidential app (it can keep a secret): JWT Grant and Confidential ACG
  integrationKey: env("DOCUSIGN_INTEGRATION_KEY"),
  secretKey: env("DOCUSIGN_SECRET_KEY"),
  userId: env("DOCUSIGN_USER_ID"),
  privateKeyPath: path.resolve(HERE, env("DOCUSIGN_PRIVATE_KEY_PATH", "private.key")),
  // The public app (it can't): PKCE
  publicIntegrationKey: env("DOCUSIGN_PUBLIC_INTEGRATION_KEY"),
  maskIds: env("MASK_IDS", "true") !== "false",
};
setMasking(CONFIG.maskIds);

/** Register each of these, exactly, on its app in the Developer Console. */
const REDIRECT = {
  jwt: `${CONFIG.appUrl}/jwt/consent`,
  acg: `${CONFIG.appUrl}/acg/callback`,
  pkce: `${CONFIG.appUrl}/pkce/callback`,
};

function privateKey() {
  try {
    return createPrivateKey(readFileSync(CONFIG.privateKeyPath));
  } catch {
    return null;
  }
}

/** What each flow still needs from .env, in words. Empty when it's ready. */
function missing(flow) {
  const todo = [];
  if (flow !== "pkce" && !CONFIG.integrationKey)
    todo.push("DOCUSIGN_INTEGRATION_KEY: the integration key of the app that answers Yes, it can store a client secret");
  if (flow === "acg" && !CONFIG.secretKey) todo.push("DOCUSIGN_SECRET_KEY: a secret key added to that app. Docusign shows it once.");
  if (flow === "jwt" && !CONFIG.userId)
    todo.push("DOCUSIGN_USER_ID: the user the JWT acts as. Your user ID is on the Apps and Keys page, and it's userinfo's sub after a Confidential ACG sign-in.");
  if (flow === "jwt" && !privateKey())
    todo.push(`The RSA private key you generated for that app, saved as ${path.relative(HERE, CONFIG.privateKeyPath)}. Docusign shows it once.`);
  if (flow === "pkce" && !CONFIG.publicIntegrationKey)
    todo.push("DOCUSIGN_PUBLIC_INTEGRATION_KEY: the integration key of the app that answers No, it can't store a client secret");
  return todo;
}

/* ── state: one person on localhost, so it lives in memory ──────────────── */

const steps = { jwt: [], acg: [] }; // what each flow's page shows, in order
const acg = { state: "", code: "", tokens: null, extended: false };

/* ── pages ───────────────────────────────────────────────────────────────── */

const NAV = [
  ["/", "Home"],
  ["/jwt", "JWT Grant"],
  ["/acg", "Confidential ACG"],
  ["/pkce", "Public ACG + PKCE"],
  ["/errors", "Errors"],
];

/** The help icon on each page opens Docusign's guide for that flow. */
const DOCS = {
  "/": "https://developers.docusign.com/platform/auth/choose/",
  "/jwt": "https://developers.docusign.com/platform/auth/jwt-get-token/",
  "/acg": "https://developers.docusign.com/platform/auth/authcode/",
  "/pkce": "https://developers.docusign.com/platform/auth/public-authcode-get-token/",
  "/errors": "https://developers.docusign.com/platform/auth/",
};

function layout({ active, title, intro = "", body, scripts = "" }) {
  const host = new URL(CONFIG.authServer).host;
  const demo = host.startsWith("account-d");
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(title)} · OAuth Flows sample</title>
<link rel="stylesheet" href="/style.css">
</head>
<body>
<header class="top">
  <a class="brand" href="/">OAuth Flows<span class="tag">Sample app</span></a>
  <nav class="tabs">${NAV.map(([href, label]) => `<a href="${href}"${href === active ? ' class="active" aria-current="page"' : ""}>${label}</a>`).join("")}</nav>
  <div class="top-right">
    <span class="host" title="Docusign authentication server">${esc(host)}</span>
    <a class="icon-btn" href="${DOCS[active]}" target="_blank" rel="noopener" title="Docusign documentation">${icon.help}</a>
  </div>
</header>
<main>
  <div class="page-head">
    <h1>${esc(title)}</h1>
    <div class="env-toggle" title="Set by DOCUSIGN_AUTH_SERVER in .env"><span${demo ? ' class="on"' : ""}>Demo</span><span${demo ? "" : ' class="on"'}>Production</span></div>
  </div>
  ${intro ? banner("info", intro) : ""}
  ${body}
</main>
<script type="module" src="/page.js"></script>
${scripts}
</body>
</html>`;
}

const postButton = (action, label, { name, value, kind = "primary" } = {}) =>
  `<form method="post" action="${action}">${name ? `<input type="hidden" name="${name}" value="${esc(value)}">` : ""}<button class="btn ${kind}">${esc(label)}</button></form>`;

/** The buttons under the steps, lined up with the right-hand column. */
const pageActions = (inner, id = "") => `<div class="page-actions"><div${id ? ` id="${id}"` : ""} class="actions">${inner}</div></div>`;

const setupStep = (todo) => ({
  title: "Finish the setup",
  state: "next",
  lead: "Add these to <code>.env</code>, then restart the server.",
  html: `<ul class="todo">${todo.map((t) => `<li>${esc(t)}</li>`).join("")}</ul>`,
});

function homePage() {
  const card = ({ href, who, title, app, flow, redirect }) => {
    const todo = missing(flow);
    return `<article class="card">
      <div class="eyebrow">${who}</div>
      <h2>${title}</h2>
      <p class="desc">${app}</p>
      ${field("Redirect URI", readonly(redirect))}
      <div class="card-foot">
        ${todo.length ? `<span class="badge danger">${todo.length} setting${todo.length > 1 ? "s" : ""} missing</span>` : `<span class="badge success">${icon.check}Ready</span>`}
        <a class="btn ${todo.length ? "quiet" : "primary"}" href="${href}">Open</a>
      </div>
    </article>`;
  };
  return layout({
    active: "/",
    title: "Docusign OAuth, three ways",
    intro: "Pick the flow that fits your architecture, then run it against your developer account. Every request and response is on the page, with IDs and tokens masked.",
    body: `
    <section class="step">
      <div class="step-side"><h2>Which flow?</h2><p class="lead">Two questions about your application decide it.</p></div>
      <div class="step-main">
        <ol class="decide">
          <li><span class="q">Does a person sign in to your application?</span><span class="a"><b>No</b> JWT Grant</span></li>
          <li><span class="q">Can your application keep a client secret safe?</span><span class="a"><b>Yes</b> Confidential ACG</span><span class="a"><b>No</b> Public ACG with PKCE</span></li>
        </ol>
      </div>
    </section>
    <div class="cards">
      ${card({ href: "/jwt", who: "No one signs in", title: "JWT Grant", app: "Scheduled jobs and background services. Confidential app with an RSA key pair.", flow: "jwt", redirect: REDIRECT.jwt })}
      ${card({ href: "/acg", who: "A person signs in · a server keeps the secret", title: "Confidential Authorization Code Grant", app: "Web apps with their own server. Confidential app with a secret key.", flow: "acg", redirect: REDIRECT.acg })}
      ${card({ href: "/pkce", who: "A person signs in · nothing can keep a secret", title: "Public Authorization Code Grant with PKCE", app: "Single-page, mobile and desktop apps. Public app with CORS.", flow: "pkce", redirect: REDIRECT.pkce })}
    </div>`,
  });
}

/** The JWT, shown as its three parts, then its claims one by one. */
function assertionHtml({ body, assertion }, brk) {
  const [h, b, s] = assertion.split(".");
  const short = (part) => (CONFIG.maskIds ? `${part.slice(0, 16)}…` : part);
  return `${field("JWT · header.payload.signature", `<div class="readonly mono jwt"><span class="j-h">${esc(h)}</span>.<span class="j-b">${esc(short(b))}</span>.<span class="j-s">${esc(short(s))}</span></div>`)}
  ${facts([
    ["iss · your integration key", mask.ids(body.iss)],
    ["sub · the user it acts as", mask.ids(body.sub)],
    ["aud · the auth server", body.aud],
    ["iat · issued at", `${body.iat} · ${clock(body.iat * 1000)}`],
    ["exp · expires", `${body.exp} · ${clock(body.exp * 1000)}`],
    ["scope", body.scope],
    ["Signed", brk?.privateKey ? "RS256 · a throwaway key" : `RS256 · ${path.basename(CONFIG.privateKeyPath)}`],
  ])}
  ${brk ? banner("note", `Broken on purpose: ${esc(brk.note)}`) : ""}`;
}

const breakButtons = (names) =>
  `<span class="break-label">Break it</span>${names
    .map((name) => postButton("/jwt/token", JWT_BREAKS[name].label, { name: "break", value: name, kind: "break" }))
    .join("")}`;

function jwtPage() {
  const todo = missing("jwt");
  let body;
  if (todo.length) body = `<div class="steps">${stepsHtml([setupStep(todo)])}</div>`;
  else {
    const shown = steps.jwt.length
      ? steps.jwt
      : [
          {
            title: "Build and sign the JWT",
            state: "next",
            lead: "Your integration, the user it acts as, and the scopes it needs, signed with the app's RSA private key.",
            html: assertionHtml(
              buildAssertion({ integrationKey: CONFIG.integrationKey, userId: CONFIG.userId, authServer: CONFIG.authServer, privateKey: privateKey() }),
            ),
          },
        ];
    const label = steps.jwt.length ? "Request a new access token" : "Request an access token";
    body = `<div class="steps">${stepsHtml(shown)}</div>
    ${pageActions(`${postButton("/jwt/token", label)}${breakButtons(["clock", "key", "environment"])}`)}`;
  }
  return layout({
    active: "/jwt",
    title: "JWT Grant",
    intro: "No one signs in. The server signs a JWT with the app's private key and trades it for a one-hour access token that acts as one user. That user consents once.",
    body,
  });
}

function acgPage() {
  const todo = missing("acg");
  let body;
  if (todo.length) body = `<div class="steps">${stepsHtml([setupStep(todo)])}</div>`;
  else {
    const preview = signInUrl({ ...CONFIG, redirectUri: REDIRECT.acg, state: "(new for every sign-in)" });
    const shown = steps.acg.length
      ? steps.acg
      : [{ title: "Send the user to Docusign to sign in", state: "next", lead: "The browser goes to Docusign's sign-in page with this URL.", request: { method: "GET", url: preview } }];
    const signIn = `<form method="get" action="/acg/login">
      <button class="btn ${acg.tokens || acg.code ? "quiet" : "primary"}">${steps.acg.length ? "Sign in again" : "Sign in with Docusign"}</button>
      <label class="check"><input type="checkbox" name="extended"${acg.extended ? " checked" : ""}> Request the extended scope</label>
    </form>`;
    const next = acg.code ? postButton("/acg/exchange", "Exchange the code") : acg.tokens ? postButton("/acg/refresh", "Refresh the token") : "";
    body = `<div class="steps">${stepsHtml(shown)}</div>${pageActions(`${next}${signIn}`)}`;
  }
  return layout({
    active: "/acg",
    title: "Confidential Authorization Code Grant",
    intro: "A person signs in. Docusign sends the browser back with a code, and the server exchanges it, with the integration key and the secret key, for an access token and a refresh token. The secret never leaves the server.",
    body,
  });
}

function pkcePage() {
  const config = { authServer: CONFIG.authServer, integrationKey: CONFIG.publicIntegrationKey, redirectUri: REDIRECT.pkce, maskIds: CONFIG.maskIds };
  return layout({
    active: "/pkce",
    title: "Public Authorization Code Grant with PKCE",
    intro: "A person signs in, and nothing can keep a secret, so PKCE takes its place. This page runs the whole flow in the browser and calls Docusign directly, over CORS.",
    body: `<div id="steps" class="steps"></div>${pageActions("", "actions")}
    <script type="application/json" id="pkce-config">${JSON.stringify(config).replaceAll("<", "\\u003c")}</script>`,
    scripts: `<script type="module" src="/pkce.js"></script>`,
  });
}

function errorsPage() {
  let n = 0;
  const section = (code, when, fix, actions) => `<section class="step">
    <div class="step-side">
      <div class="step-num"><span class="n">${++n}</span></div>
      <h2 class="code-title">${esc(code)}</h2>
      <p class="lead">${when}</p>
    </div>
    <div class="step-main">
      ${field("How to fix it", `<p class="text">${fix}</p>`)}
      ${field("Cause it here", `<div class="actions">${actions}</div>`)}
    </div>
  </section>`;
  return layout({
    active: "/errors",
    title: "Reading the errors",
    intro: "The five errors from the tutorial, and a way to cause each one here, safely, against your developer account.",
    body: `<div class="steps">
    ${section(
      "consent_required",
      "The user hasn't granted consent, or you're requesting a scope they haven't approved. It can also mean consent was granted as the wrong user.",
      "With JWT Grant, request <code>signature impersonation</code> and check the consent URL's integration key. Add <code>prompt=login</code> so Docusign asks who is signing in.",
      `<a class="btn quiet" href="/jwt">Run JWT Grant before consenting</a><span class="aside">Already consented? Revoke the app's consent from your Docusign profile to see it again.</span>`,
    )}
    ${section(
      "invalid_grant: Origin required but not included",
      "A single-page app using CORS sent a token request with no Origin header.",
      "Every token request has to send an Origin header that matches an origin URL in the app's CORS settings. Browsers add it themselves.",
      `<a class="btn quiet" href="/pkce">Open the PKCE page</a><span class="aside">After sign-in, choose “from a server, no Origin”.</span>`,
    )}
    ${section(
      "invalid_grant",
      "With JWT Grant it arrives as <code>no_valid_keys_or_signatures</code>: the issued-at or expiry time is wrong, usually a drifting server clock, or the RSA key is wrong. With an Authorization Code Grant, the code expired, was truncated, or the PKCE verifier doesn't match.",
      "Sync the server clock. Use the RSA key from this app and this environment. Exchange codes within two minutes.",
      `${postButton("/jwt/token", JWT_BREAKS.clock.label, { name: "break", value: "clock", kind: "break" })}${postButton("/jwt/token", JWT_BREAKS.key.label, { name: "break", value: "key", kind: "break" })}<span class="aside">Or wait out the two minutes before exchanging a code, or send “a different verifier” on the PKCE page.</span>`,
    )}
    ${section(
      "The response type is not supported",
      "The app's authentication settings don't match the flow the code runs.",
      "Match the code to the app: an Authorization Code Grant app answers <code>response_type=code</code>.",
      `<a class="btn break" href="/errors/response-type">Ask this app for an Implicit Grant token</a>`,
    )}
    ${section(
      "400 Bad Request on the token call",
      "Often the wrong environment's endpoint.",
      "Developer accounts authenticate at <code>account-d.docusign.com</code>, production at <code>account.docusign.com</code>.",
      postButton("/jwt/token", JWT_BREAKS.environment.label, { name: "break", value: "environment", kind: "break" }),
    )}
    </div>`,
  });
}

/* ── JWT Grant ───────────────────────────────────────────────────────────── */

const consentStep = () => {
  const url = consentUrl({ authServer: CONFIG.authServer, integrationKey: CONFIG.integrationKey, redirectUri: REDIRECT.jwt });
  return {
    title: "Grant consent, once",
    state: "next",
    lead: "The user the JWT acts as signs in and accepts. Docusign remembers that until it's revoked, so this happens once.",
    request: { method: "GET", url },
    html: `<div class="actions inline"><a class="btn primary" href="${esc(url)}">Open the consent page</a></div>`,
  };
};

async function runJwt(breakName) {
  const brk = JWT_BREAKS[breakName];
  const authServer = brk?.authServer ?? CONFIG.authServer;
  const shown = (steps.jwt = []);

  const jwt = buildAssertion({
    integrationKey: CONFIG.integrationKey,
    userId: CONFIG.userId,
    authServer,
    privateKey: brk?.privateKey?.() ?? privateKey(),
    now: brk?.now?.(),
  });
  shown.push({ title: "Build and sign the JWT", state: "done", html: assertionHtml(jwt, brk) });

  const request = jwtTokenRequest(authServer, jwt.assertion);
  const result = await send(request);
  if (!result.ok) {
    shown.push({ title: "Exchange it for an access token", state: "error", request, response: result, hint: explain(result) });
    if (result.body.error === "consent_required") shown.push(consentStep());
    return;
  }
  shown.push({
    title: "Exchange it for an access token",
    state: "done",
    request,
    response: result,
    html: tokenFacts(result.body, {
      refresh: "none · JWT Grant doesn't issue refresh tokens",
      renewBefore: { label: "Request a new one by (15 minutes early)", seconds: 15 * 60 },
    }),
  });
  await useToken(shown, authServer, result.body.access_token);
}

/** Docusign sends the browser here after consent, with a code JWT Grant never uses. */
function jwtConsentReturned(url) {
  const consent = steps.jwt.find((s) => s.title === "Grant consent, once");
  if (consent) Object.assign(consent, { state: "done", html: "" });
  const error = url.searchParams.get("error");
  steps.jwt.push(
    error
      ? { title: "Back at the redirect URI", state: "error", error, request: { method: "GET", url: url.href }, hint: url.searchParams.get("error_description") ?? "" }
      : {
          title: "Back at the redirect URI: consent recorded",
          state: "done",
          request: { method: "GET", url: url.href },
          lead: "JWT Grant doesn't use this code. Consent is recorded on Docusign's side, and that's all this step was for. With a redirect URI nothing serves, this is the page that fails to load: you can close it.",
        },
  );
}

/* ── Confidential Authorization Code Grant ──────────────────────────────── */

function acgSignIn(extended) {
  Object.assign(acg, { state: randomBytes(16).toString("hex"), code: "", tokens: null, extended });
  const url = signInUrl({ ...CONFIG, redirectUri: REDIRECT.acg, state: acg.state, extended });
  steps.acg = [{ title: "Send the user to Docusign to sign in", state: "done", request: { method: "GET", url } }];
  return url;
}

function acgReturned(url) {
  const code = url.searchParams.get("code");
  if (code && code === acg.code) return; // a reload: nothing new
  const error = url.searchParams.get("error");
  const redirect = { method: "GET", url: url.href };
  if (error || !code || url.searchParams.get("state") !== acg.state) {
    const body = error
      ? { error, error_description: url.searchParams.get("error_description") ?? "" }
      : { error: code ? "state_mismatch" : "no_code", error_description: "This redirect doesn't belong to the sign-in this app started." };
    steps.acg.push({ title: "Back at the redirect URI", state: "error", error: body.error, request: redirect, hint: explain({ status: 400, body }) || body.error_description });
    return;
  }
  Object.assign(acg, { code, state: "" });
  steps.acg.push({
    title: "Back at the redirect URI with an authorization code",
    state: "next",
    request: redirect,
    lead: "A real server exchanges it straight away. Here, you press the button.",
    html: facts([["Code valid for", { html: countdown(Date.now() + 120 * 1000) }]]),
  });
}

const ACG_REFRESH = () => ({
  refresh: acg.extended ? "yes · extended scope: each refresh renews its full lifetime" : "yes · 30 days by default. Refreshing doesn't extend that.",
  renewBefore: { label: "Refresh by (30 minutes early)", seconds: 30 * 60 },
});

async function acgExchange() {
  const codeStep = steps.acg.findLast((s) => s.state === "next");
  if (codeStep) Object.assign(codeStep, { state: "done", html: facts([["Code", "used: a code works once"]]) });
  const request = codeExchangeRequest({ ...CONFIG, code: acg.code });
  acg.code = "";
  const result = await send(request);
  if (!result.ok) {
    steps.acg.push({ title: "Exchange the code for tokens", state: "error", request, response: result, hint: explain(result) });
    return;
  }
  acg.tokens = result.body;
  steps.acg.push({ title: "Exchange the code for tokens", state: "done", request, response: result, html: tokenFacts(result.body, ACG_REFRESH()) });
  await useToken(steps.acg, CONFIG.authServer, result.body.access_token);
}

async function acgRefresh() {
  const request = refreshRequest({ ...CONFIG, refreshToken: acg.tokens.refresh_token });
  const result = await send(request);
  if (result.ok) acg.tokens = result.body;
  steps.acg.push({
    title: "Refresh the access token",
    state: result.ok ? "done" : "error",
    lead: "No sign-in. Docusign returns a new access token and a new refresh token.",
    request,
    response: result,
    hint: result.ok ? "" : explain(result),
    html: result.ok ? tokenFacts(result.body, ACG_REFRESH()) : "",
  });
}

/* ── PKCE: only one server route, to show what happens without a browser ─ */

async function pkceWithoutOrigin(form) {
  if (form.grant_type !== "authorization_code" || form.client_id !== CONFIG.publicIntegrationKey) return { ok: false, status: 400, body: { error: "not_this_demo" } };
  return send(tokenRequest(CONFIG.authServer, form)); // Node's fetch sends no Origin header
}

/* ── HTTP ───────────────────────────────────────────────────────────────── */

const STATIC = {
  "/style.css": ["public/style.css", "text/css"],
  "/page.js": ["public/page.js", "text/javascript"],
  "/pkce.js": ["public/pkce.js", "text/javascript"],
  "/shared/docusign.js": ["shared/docusign.js", "text/javascript"],
  "/shared/view.js": ["shared/view.js", "text/javascript"],
};

async function readBody(req) {
  let data = "";
  for await (const chunk of req) data += chunk;
  return data;
}

const html = (res, page) => res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" }).end(page);
const redirect = (res, location, status = 303) => res.writeHead(status, { Location: location }).end();

async function route(req, res) {
  const url = new URL(req.url, CONFIG.appUrl);
  const key = `${req.method} ${url.pathname.replace(/(.)\/$/, "$1")}`;

  if (req.method === "GET" && STATIC[url.pathname]) {
    const [file, type] = STATIC[url.pathname];
    return res.writeHead(200, { "Content-Type": `${type}; charset=utf-8`, "Cache-Control": "no-store" }).end(await readFile(path.join(HERE, file)));
  }

  switch (key) {
    case "GET /":
      return html(res, homePage());
    case "GET /errors":
      return html(res, errorsPage());
    case "GET /errors/response-type":
      return redirect(res, authorizeUrl(CONFIG.authServer, { response_type: "token", scope: "signature", client_id: CONFIG.integrationKey, redirect_uri: REDIRECT.acg }), 302);

    case "GET /jwt":
      return html(res, jwtPage());
    case "POST /jwt/token":
      if (!missing("jwt").length) await runJwt(new URLSearchParams(await readBody(req)).get("break"));
      return redirect(res, "/jwt");
    case "GET /jwt/consent":
      jwtConsentReturned(url);
      return html(res, jwtPage());

    case "GET /acg":
      return html(res, acgPage());
    case "GET /acg/login":
      return missing("acg").length ? redirect(res, "/acg") : redirect(res, acgSignIn(url.searchParams.get("extended") === "on"), 302);
    case "GET /acg/callback":
      acgReturned(url);
      return html(res, acgPage());
    case "POST /acg/exchange":
      if (acg.code) await acgExchange();
      return redirect(res, "/acg");
    case "POST /acg/refresh":
      if (acg.tokens) await acgRefresh();
      return redirect(res, "/acg");

    case "GET /pkce":
    case "GET /pkce/callback":
      return html(res, pkcePage());
    case "POST /pkce/no-origin":
      return res.writeHead(200, { "Content-Type": "application/json" }).end(JSON.stringify(await pkceWithoutOrigin(JSON.parse((await readBody(req)) || "{}"))));
  }
  res.writeHead(404, { "Content-Type": "text/plain" }).end("Not found");
}

const server = createServer((req, res) =>
  route(req, res).catch((err) => {
    console.error(err);
    if (!res.headersSent) res.writeHead(500, { "Content-Type": "text/plain; charset=utf-8" }).end(`Something broke: ${err.message}`);
  }),
);

const { hostname, port } = new URL(CONFIG.appUrl);
server.listen(Number(port) || 80, hostname, () => {
  const status = (flow) => (missing(flow).length ? `missing ${missing(flow).length} setting(s): open the page for details` : "ready");
  console.log(`\nDocusign OAuth sample · ${CONFIG.appUrl}\n`);
  console.log(`  JWT Grant              ${status("jwt")}`);
  console.log(`  Confidential ACG       ${status("acg")}`);
  console.log(`  Public ACG + PKCE      ${status("pkce")}\n`);
});
