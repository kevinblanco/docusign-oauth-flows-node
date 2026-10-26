# Docusign OAuth, three ways

One local app that runs each Docusign OAuth flow against your developer account and shows every request and response along the way:

- **JWT Grant.** No one signs in. Your server signs a JWT with an RSA private key and trades it for a one-hour access token that acts as one user.
- **Confidential Authorization Code Grant.** A person signs in, and your server exchanges the code with its secret key for an access token and a refresh token.
- **Public Authorization Code Grant with PKCE.** A person signs in to a single-page app that can't keep a secret. A code verifier and its SHA-256 challenge take the secret's place. The whole flow runs in the browser, over CORS.

There's no SDK and nothing to install. It needs Node.js 20.12 or later, which has `fetch` and `crypto` built in. IDs and tokens are masked on the page, so it's safe to share or screenshot.

## Which flow?

1. Does a person sign in to your application? **No**: JWT Grant.
2. **Yes**: can your application keep a client secret safe? **Yes**: Confidential. **No**: Public, with PKCE.

## Set up two apps

You need a [Docusign developer account](https://developers.docusign.com). Configure both apps in Apps and Keys. Docusign calls each app's ID the integration key; the Developer Console labels it **Client ID**. Each integration key answers the client-secret question once, and the browser flow has to answer **No**, so it gets an app of its own.

### App 1: the server (JWT Grant and Confidential ACG)

1. Add an app and integration key. Name it so you'll recognize it on a consent screen.
2. *Is your application able to securely store a client secret?* **Yes**.
3. Authentication method: **Authorization Code Grant**. Leave *Require PKCE* off.
4. **Add secret key.** Copy it into `DOCUSIGN_SECRET_KEY`. Docusign shows it once.
5. **Generate RSA** key pair. Save the private key, including its `BEGIN` and `END` lines, as `private.key` in this folder. Docusign shows it once.
6. Add two redirect URIs, exactly as written:
   - `http://localhost:3000/jwt/consent`
   - `http://localhost:3000/acg/callback`
7. Save. Copy the Client ID (the integration key) into `DOCUSIGN_INTEGRATION_KEY`, and your user ID from the same page into `DOCUSIGN_USER_ID`.

### App 2: the browser (Public ACG with PKCE)

1. Add a second app and integration key.
2. *Is your application able to securely store a client secret?* **No**.
3. App type: **Single Page Web Application**. Authentication method: **Authorization Code Grant with PKCE**.
4. Add the redirect URI `http://localhost:3000/pkce/callback`.
5. CORS configuration:
   - Origin URL: `http://localhost:3000`
   - Allowed HTTP methods: **GET** and **POST**
   - Select **Allow CORS for OAuth calls**
6. Save. Copy its Client ID (the integration key) into `DOCUSIGN_PUBLIC_INTEGRATION_KEY`.

New secret keys, RSA keys, redirect URIs and CORS settings take up to five minutes to apply.

## Run it

```bash
cp .env.example .env     # then fill it in
npm start                # http://localhost:3000
```

The start page shows which flows are ready, and each flow's page says what's still missing.

The pages follow the look of Docusign's web app and Developer Console. They use Docusign's DS Indigo typeface if it's installed on your machine. The font isn't included here, so without it the pages fall back to Helvetica or Arial.

## What each page does

| Page | Steps |
|---|---|
| `/jwt` | Build and sign the JWT (`iss`, `sub`, `aud`, `iat`, `exp`, `scope=signature impersonation`) → `POST /oauth/token`. The first time, Docusign answers `consent_required` and the page gives you the consent URL. Accept once, then request again → `GET /oauth/userinfo` → one eSignature REST API call. |
| `/acg` | Redirect to `/oauth/auth` → back at `/acg/callback` with `?code=`, and a two-minute countdown → `POST /oauth/token` with Basic auth (integration key and secret key) → access token and refresh token → userinfo → one API call → **Refresh**. Tick *extended scope* to have each refresh renew the refresh token's full lifetime. |
| `/pkce` | Generate the code verifier → hash it into the code challenge (SHA-256, Base64URL) → sign in with `code_challenge` and `code_challenge_method=S256` → exchange the code with `code_verifier` and no secret, straight from the browser → userinfo and one API call, over CORS → **Refresh**. |
| `/errors` | Five common errors, and a way to cause each one. |

## Break it on purpose

| Error | How to cause it here |
|---|---|
| `consent_required` | Run JWT Grant before you consent. |
| `invalid_grant: Origin required but not included` | On the PKCE page, after sign-in: *from a server, no Origin*. |
| `invalid_grant` / `no_valid_keys_or_signatures` | JWT Grant: *a server clock two hours slow*, or *an RSA key Docusign has never seen*. ACG: wait out the two-minute countdown. PKCE: *a different verifier*. |
| *The response type is not supported* | `/errors`: ask the Authorization Code Grant app for an Implicit Grant token. |
| `400 Bad Request` on the token call | JWT Grant: *the production endpoint*. |

## Files

```
server.js            routes and pages. JWT Grant and Confidential ACG run here.
flows/jwt.js         JWT Grant: build and sign the assertion, the consent URL
flows/authcode.js    Confidential ACG: sign-in URL, code exchange, refresh
public/pkce.js       Public ACG with PKCE, entirely in the browser
shared/docusign.js   the calls every flow shares: /oauth/auth, /oauth/token, /oauth/userinfo
shared/view.js       masking, error explanations, and the HTML for each step
```

`shared/` runs in Node and in the browser unchanged.

## Before you take this to production

This is a teaching app. It serves one person on localhost and keeps tokens in memory. For production:

- Authenticate at `account.docusign.com`, and keep reading the base URI from `/oauth/userinfo`.
- Go-Live copies the integration key but none of its secrets. Create new secret keys and RSA key pairs, and add your redirect URIs again.
- Consent starts over in production.
- For JWT Grant, the user you impersonate has a different user ID in production.

## Settings

| Variable | |
|---|---|
| `DOCUSIGN_INTEGRATION_KEY` | App 1's integration key |
| `DOCUSIGN_SECRET_KEY` | A secret key on App 1 |
| `DOCUSIGN_USER_ID` | The user JWT Grant acts as |
| `DOCUSIGN_PRIVATE_KEY_PATH` | App 1's RSA private key. Default `private.key` |
| `DOCUSIGN_PUBLIC_INTEGRATION_KEY` | App 2's integration key |
| `DOCUSIGN_AUTH_SERVER` | Default `https://account-d.docusign.com` |
| `APP_URL` | Default `http://localhost:3000`. The redirect URIs are built from it. |
| `MASK_IDS` | `false` shows IDs and tokens in full. Secret keys never appear. |

`.env` and `private.key` are gitignored. Keep them out of your repository.

## Docusign documentation

- [Choose an OAuth type](https://developers.docusign.com/platform/auth/choose/)
- [How to get an access token with JWT Grant](https://developers.docusign.com/platform/auth/jwt-get-token/)
- [Authorization Code Grant](https://developers.docusign.com/platform/auth/authcode/)
- [How to get an access token using Public Authorization Code Grant](https://developers.docusign.com/platform/auth/public-authcode-get-token/)
- [Single-page applications and CORS](https://developers.docusign.com/platform/single-page-applications-cors/)
- [Configure your app](https://developers.docusign.com/platform/configure-app/)
- [Obtain and revoke consent](https://developers.docusign.com/platform/auth/consent/)

## License

MIT. See [LICENSE](LICENSE).
