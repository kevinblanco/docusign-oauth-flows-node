// How the app shows what goes over the wire: masking, error explanations, and
// the HTML for one step. No DOM calls, so server.js and the PKCE page share it.

/* ── masking: IDs, tokens and secrets never show in full on the page ───── */

const GUID = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi;
const EMAIL = /^[^@\s]+@[^@\s]+$/;
/** Fields whose values are credentials: shown as their first characters only. */
const CREDENTIALS = new Set(["access_token", "refresh_token", "id_token", "assertion", "code"]);

let masking = true;
export const setMasking = (on) => {
  masking = on;
};

export const mask = {
  /** Every GUID in a string, the way Docusign's docs mask an account ID: 18b4799a-xxxx-xxxx-xxxx-b5b4b8a97604 */
  ids: (s) => (masking ? String(s).replace(GUID, (g) => `${g.slice(0, 8)}-xxxx-xxxx-xxxx-${g.slice(-12)}`) : String(s)),
  token: (s) => {
    s = String(s);
    return masking && s.length > 24 ? `${s.slice(0, 12)}… (${s.length.toLocaleString("en-US")} characters)` : s;
  },
  email: (s) => (masking ? String(s).replace(/^(.)[^@]*/, "$1•••") : String(s)),
  /** Secret keys never appear, masked or not. */
  secret: () => "••••••••",
};

/** A copy of a value with every credential, ID and email masked. */
export function redact(value, key = "") {
  if (Array.isArray(value)) return value.map((v) => redact(v));
  if (value && typeof value === "object") return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, redact(v, k)]));
  if (typeof value !== "string") return value;
  if (key === "client_secret") return mask.secret();
  if (CREDENTIALS.has(key)) return mask.token(value);
  if (EMAIL.test(value)) return mask.email(value);
  return mask.ids(value);
}

/* ── what an error means: the common causes, and how to fix each ───────── */

export function explain({ status, body = {} }) {
  const error = String(body.error ?? "").toLowerCase();
  const detail = String(body.error_description ?? body.message ?? "");
  if (status === 0)
    return `No response reached the page: the browser hid Docusign's answer because it had no CORS header. Check the app's origin URL (${globalThis.location?.origin ?? "http://localhost:3000"}), its allowed methods (GET and POST), and that Allow CORS for OAuth calls is selected. Changes take up to five minutes to apply. To read Docusign's actual answer, start over, sign in, and send the code from a server.`;
  if (error === "consent_required")
    return "The user hasn't approved these scopes for this integration key yet, or approved them as someone else. Open the consent URL once. prompt=login makes Docusign ask who is signing in.";
  if (/origin/i.test(detail))
    return "A single-page app with CORS must send an Origin header that matches an origin URL in the app's CORS settings. Browsers add it. Servers don't.";
  if (/no_valid_keys_or_signatures/i.test(detail))
    return "The JWT didn't verify. Most often iat or exp is wrong because the server clock drifted. Or the RSA key is wrong: created for the other environment, revoked, or from another app.";
  if (/user_not_found/.test(`${error} ${detail}`))
    return "Docusign has no user with this ID in this environment. For JWT Grant, sub must be a User ID, not the API Account ID next to it, and from the same environment as the endpoint.";
  if (/issuer_not_found/.test(`${error} ${detail}`))
    return "This integration key doesn't exist in this environment: often the wrong endpoint. Developer accounts authenticate at account-d.docusign.com, production at account.docusign.com.";
  if (error === "invalid_grant")
    return "Docusign refused the grant. With an Authorization Code Grant: the code expired (two minutes), was truncated or was already used, or the PKCE code verifier doesn't match the challenge. Sign in again.";
  if (error === "invalid_request")
    return "Often the PKCE code verifier doesn't match the code challenge. The challenge must be SHA-256 of the verifier, Base64URL-encoded.";
  if (error === "invalid_client")
    return "Docusign doesn't accept this integration key and secret key together. A new secret key takes up to five minutes to apply.";
  if (/response.?type/i.test(`${error} ${detail}`))
    return "The app's authentication settings in the Developer Console don't match the flow this code runs.";
  if (status === 400)
    return "A bad request on the token call often means the wrong environment: developer accounts authenticate at account-d.docusign.com, production at account.docusign.com.";
  if (status === 401) return "The access token is missing, expired, or from the other environment.";
  return "";
}

/* ── HTML: the parts of a Docusign Developer Console page ─────────────── */

export const esc = (s) =>
  String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);

const REASONS = { 200: "OK", 201: "Created", 400: "Bad Request", 401: "Unauthorized", 403: "Forbidden", 404: "Not Found", 429: "Too Many Requests" };

/** "1 hour", "8 hours", "2 minutes". */
export function duration(seconds) {
  const [n, unit] = seconds >= 3600 ? [seconds / 3600, "hour"] : [Math.round(seconds / 60), "minute"];
  const rounded = Math.round(n * 10) / 10;
  return `${rounded} ${unit}${rounded === 1 ? "" : "s"}`;
}

export const clock = (ms) => new Date(ms).toLocaleTimeString("en-US", { hour: "numeric", minute: "2-digit", second: "2-digit" });

/** A live "1:42 left" that page.js counts down. */
export const countdown = (untilMs) => `<span class="countdown" data-until="${untilMs}">…</span>`;

const svg = (body) =>
  `<svg class="icon" viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${body}</svg>`;

export const icon = {
  info: svg('<circle cx="12" cy="12" r="9"/><path d="M12 11v5"/><circle cx="12" cy="7.8" r=".6" fill="currentColor"/>'),
  alert: svg('<path d="M12 3.5 2.8 19.5h18.4z"/><path d="M12 10v4.2"/><circle cx="12" cy="16.9" r=".6" fill="currentColor"/>'),
  check: svg('<path d="m5 12.5 4.5 4.5L19 7.5"/>'),
  help: svg('<circle cx="12" cy="12" r="9"/><path d="M9.6 9.4a2.5 2.5 0 1 1 3.4 2.3c-.6.3-1 .8-1 1.5v.4"/><circle cx="12" cy="16.9" r=".6" fill="currentColor"/>'),
};

/** A banner: "info" (lavender), "note" (grey) or "danger". `html` is markup. */
export const banner = (kind, html) =>
  `<div class="banner ${kind}">${kind === "danger" ? icon.alert : icon.info}<div>${html}</div></div>`;

/** A labelled field, like the Developer Console's read-only Client ID. */
export const field = (label, inner, help = "") =>
  `<div class="field"><div class="label">${label}</div>${inner}${help ? `<div class="help">${help}</div>` : ""}</div>`;

/** Text in a read-only box. */
export const readonly = (text, { mono = true } = {}) => `<div class="readonly${mono ? " mono" : ""}">${esc(text)}</div>`;

/** Label/value fields in a grid. A value is text, or { html } for markup you built yourself. */
export const facts = (rows) =>
  `<div class="fields">${rows
    .filter(Boolean)
    .map(([k, v]) => field(esc(k), v && typeof v === "object" ? `<div class="readonly mono">${v.html}</div>` : readonly(v)))
    .join("")}</div>`;

function headerValue(name, value) {
  if (!/^authorization$/i.test(name)) return value;
  const [scheme, credential = ""] = value.split(" ");
  if (scheme === "Bearer") return `Bearer ${mask.token(credential)}`;
  if (scheme === "Basic") return `Basic base64(${mask.ids(atob(credential).split(":")[0])}:${mask.secret()})`;
  return value;
}

/** A request the way it goes over the wire: one query parameter, header or form field per line. */
export function requestHtml({ method, url, headers = {}, form, implicitHeaders = {} }) {
  const [base, query] = url.split("?");
  const params = query ? query.split("&").map((p) => p.split("=")).map(([k, v = ""]) => [k, decodeURIComponent(v)]) : [];
  const lines = [
    `<div class="line"><b class="verb">${esc(method)}</b> ${esc(mask.ids(base))}</div>`,
    ...params.map(([k, v], i) => `<div class="line q">${i ? "&amp;" : "?"}<span class="k">${esc(k)}</span>=${esc(redact(v, k))}</div>`),
    ...Object.entries(headers).map(([k, v]) => `<div class="line h"><span class="k">${esc(k)}:</span> ${esc(headerValue(k, v))}</div>`),
    ...Object.entries(implicitHeaders).map(([k, v]) => `<div class="line h implicit"><span class="k">${esc(k)}:</span> ${esc(v)}</div>`),
  ];
  if (form)
    lines.push(
      `<div class="body">${Object.entries(form)
        .map(([k, v]) => `<div class="line"><span class="k">${esc(k)}</span>=${esc(redact(v, k))}</div>`)
        .join("")}</div>`,
    );
  return field("Request", `<div class="http">${lines.join("")}</div>`);
}

const highlight = (json) => esc(json).replace(/^(\s*)(&quot;.*?&quot;)(:)/gm, '$1<span class="k">$2</span>$3');

/** A response: its status, then its JSON with credentials masked. `show` limits it to some fields. */
export function responseHtml({ status, body = {}, show }) {
  let shown = show ? Object.fromEntries(show.filter((k) => k in body).map((k) => [k, body[k]])) : body;
  if (typeof shown.text === "string") shown = { text: `${shown.text.slice(0, 280)}${shown.text.length > 280 ? "…" : ""}` };
  const label = status ? `${status} ${REASONS[status] ?? ""}` : "No response";
  return field(
    `Response <span class="status s${String(status)[0]}">${esc(label)}</span>`,
    `<pre class="code">${highlight(JSON.stringify(redact(shown), null, 2))}</pre>`,
    show ? `Showing ${esc(show.join(", "))} only` : "",
  );
}

/**
 * One numbered step, laid out like a Developer Console section: what it is on
 * the left, what went over the wire on the right.
 * step = { title, state: "done" | "error" | "next" | "todo", error?, lead?, request?, response?, hint?, html? }
 * `lead` and `html` are markup: escape anything in them that came from outside.
 */
export function stepHtml(n, step) {
  const error = step.error ?? step.response?.body?.error;
  const badge =
    step.state === "done"
      ? `<span class="badge success">${icon.check}Done</span>`
      : step.state === "error"
        ? `<span class="badge danger">${esc(error ?? (step.response?.status || "Error"))}</span>`
        : step.state === "next"
          ? `<span class="badge info">Next</span>`
          : "";
  return `<section class="step is-${esc(step.state)}">
    <div class="step-side">
      <div class="step-num"><span class="n">${n}</span>${badge}</div>
      <h2>${esc(step.title)}</h2>
      ${step.lead ? `<p class="lead">${step.lead}</p>` : ""}
    </div>
    <div class="step-main">
      ${step.request ? requestHtml(step.request) : ""}
      ${step.response ? responseHtml(step.response) : ""}
      ${step.hint ? banner(step.state === "error" ? "danger" : "note", esc(step.hint)) : ""}
      ${step.html ?? ""}
    </div>
  </section>`;
}

export const stepsHtml = (steps) => steps.map((s, i) => stepHtml(i + 1, s)).join("");
