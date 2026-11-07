# o2js

**A lightweight, provider-agnostic OAuth2 and OpenID Connect library for Node.js.**

o2js provides the core OAuth2 Authorization Code and Refresh Token flows, along with OpenID Connect ID Token validation.

It does not manage users, sessions, token storage, or database operations. It handles protocol mechanics and leaves application state and lifecycle management to your application.

## Installation

```bash
npm install @o2js/core
```

## Quick Start

First, define a provider:

```typescript
import type { Provider } from "@o2js/core";

const provider: Provider = {
    authURL: "https://example.com/oauth/authorize",
    tokenURL: "https://example.com/oauth/token",
};
```

Create an OAuth2 client:

```typescript
import { OAuth2 } from "@o2js/core";

const oauth = new OAuth2(provider, {
    clientID: "your-client-id",
    clientSecret: "your-client-secret",
    redirectURL: "https://yourapp.com/callback",
});
```

Generate an authorization URL:

```typescript
const state = "your-random-state";
const url = oauth.authCodeURL(state);
```

After the user authorizes your application, exchange the authorization code:

```typescript
const response = await oauth.exchangeAuthCode(code);

console.log(response.data);
```

Refresh an access token:

```typescript
const response = await oauth.exchangeRefreshToken(refreshToken);
```

## Configuration

```typescript
type ClientAuthMethod =
    | "client_secret_basic"
    | "client_secret_post";

type Config = {
    clientID: string;
    clientSecret: string;
    redirectURL: string;
    clientAuthMethod?: ClientAuthMethod;
};
```

- `clientID`: OAuth application client ID.
- `clientSecret`: OAuth application client secret.
- `redirectURL`: Registered callback URL.
- `clientAuthMethod`: Client authentication method used at the token endpoint.

Supported client authentication methods:

- `client_secret_basic`: Sends client credentials using HTTP Basic Authentication. This is the default.
- `client_secret_post`: Sends client credentials in the request body.

Example using `client_secret_post`:

```typescript
const oauth = new OAuth2(provider, {
    clientID: "your-client-id",
    clientSecret: "your-client-secret",
    redirectURL: "https://yourapp.com/callback",
    clientAuthMethod: "client_secret_post",
});
```

If `clientAuthMethod` is omitted, o2js uses `client_secret_basic`.

## Custom Parameters

OAuth providers may require additional parameters for scopes, PKCE, or other features.

You can pass additional parameters directly to the relevant methods.

Authorization URL parameters:

```typescript
const url = oauth.authCodeURL(state, {
    scope: "profile email",
    prompt: "consent",
});
```

Token request parameters:

```typescript
const response = await oauth.exchangeAuthCode(code, {
    code_verifier: "your-code-verifier",
});
```

Refresh token requests also accept additional parameters:

```typescript
const response = await oauth.exchangeRefreshToken(refreshToken, {
    custom_parameter: "value",
});
```

Check your provider's documentation for supported parameters and their expected values.

## State, Nonce and PKCE

o2js provides helpers for generating cryptographically secure random state, nonce, and PKCE values.

### State

Generate a random state value:

```typescript
import { generateRandomState } from "@o2js/core";

const state = generateRandomState();
```

Pass it to the authorization URL:

```typescript
const url = oauth.authCodeURL(state);
```

Your application is responsible for storing the state and verifying the returned value during the callback.

### Nonce

Generate a random nonce:

```typescript
import { generateRandomNonce } from "@o2js/core";

const nonce = generateRandomNonce();
```

Include it in the authorization request:

```typescript
const url = oauth.authCodeURL(state, {
    nonce,
});
```

After receiving the ID Token, pass the expected nonce to `parseClaims`:

```typescript
const claims = await oauth.parseClaims(idToken, {
    nonce,
});
```

o2js verifies that the nonce in the ID Token matches the expected value.

Your application is responsible for storing and managing the nonce throughout the authorization flow.

### PKCE

Generate PKCE parameters:

```typescript
import { generateRandomPKCE } from "@o2js/core";

const pkce = generateRandomPKCE();
```

Use the generated values in the authorization URL:

```typescript
const url = oauth.authCodeURL(state, {
    code_challenge: pkce.codeChallenge,
    code_challenge_method: "S256",
});
```

Send the code verifier when exchanging the authorization code:

```typescript
const response = await oauth.exchangeAuthCode(code, {
    code_verifier: pkce.codeVerifier,
});
```

State, nonce, and PKCE values must be stored and managed by your application. Your application is also responsible for verifying the returned state and managing the lifecycle of these values.

o2js does not store or manage these values.

## OpenID Connect

o2js supports OpenID Connect ID Token validation through the `parseClaims` method.

To enable ID Token validation, provide the issuer and JWKS URLs in your provider configuration:

```typescript
import type { Provider } from "@o2js/core";

const provider: Provider = {
    authURL: "https://example.com/oauth/authorize",
    tokenURL: "https://example.com/oauth/token",
    issuerURL: "https://example.com",
    jwksURL: "https://example.com/.well-known/jwks.json",
};
```

The `issuerURL` and `jwksURL` properties are optional for OAuth2-only providers. They are required when using `parseClaims`.

### ID Token Validation

After exchanging the authorization code, retrieve the ID Token from the token response and validate it:

```typescript
const response = await oauth.exchangeAuthCode(code);

const idToken = response.data.id_token;

if (typeof idToken !== "string") {
    throw new Error("ID Token is missing");
}

const claims = await oauth.parseClaims(idToken);

console.log(claims.sub);
```

`parseClaims` verifies the ID Token signature using the provider's JWKS and validates its issuer, audience, expiration, and required claims.

### Validation Options

The `parseClaims` method accepts an optional options object:

```typescript
type ParseClaimsOptions = {
    nonce?: string;
    maxAge?: number;
    trustedAudiences?: string[];
    algorithms?: (
        | "RS256"
        | "PS256"
        | "ES256"
        | "ES384"
        | "ES512"
    )[];
};
```

**Nonce**

If a nonce was included in the authorization request, pass the expected value when validating the ID Token:

```typescript
const claims = await oauth.parseClaims(idToken, {
    nonce: savedNonce,
});
```

The nonce must match the value in the ID Token.

**Maximum Authentication Age**

If you request a maximum authentication age, include `max_age` in the authorization request:

```typescript
const url = oauth.authCodeURL(state, {
    max_age: "300",
});
```

Pass the same value to `parseClaims`:

```typescript
const claims = await oauth.parseClaims(idToken, {
    maxAge: 300,
});
```

When `maxAge` is provided, `auth_time` is required and checked against the requested maximum age.

**Trusted Audiences**

By default, o2js accepts the configured client ID as a trusted audience.

If your application expects additional audiences, specify them explicitly:

```typescript
const claims = await oauth.parseClaims(idToken, {
    trustedAudiences: [
        "trusted-service",
    ],
});
```

Any audience not included in the client ID or the trusted audience list is rejected.

**Signing Algorithms**

The default signing algorithm is `RS256`.

You can specify additional supported algorithms:

```typescript
const claims = await oauth.parseClaims(idToken, {
    algorithms: ["RS256", "PS256", "ES256"],
});
```

Only use algorithms supported and expected by your identity provider.

### ID Token Claims

The `parseClaims` method returns an `IDTokenClaims` object:

```typescript
import type { IDTokenClaims } from "@o2js/core";
```

The type extends `JWTPayload` and includes the standard claims:

- `iss`: Issuer identifier.
- `sub`: Subject identifier.
- `aud`: Intended audience.
- `exp`: Expiration time.
- `iat`: Issued-at time.

Other claims provided by the identity provider are also available through the returned payload.

## Response

Token exchange methods return an `ExchangeResponse`:

```typescript
type ExchangeResponse = {
    raw: string;
    data: Record<string, unknown>;
};
```

- `raw`: Raw response body.
- `data`: Parsed JSON response.

## Error Handling

HTTP and token response parsing errors are represented by `HTTPError`.

```typescript
import { HTTPError } from "@o2js/core";

try {
    const response = await oauth.exchangeAuthCode(code);
} catch (error) {
    if (error instanceof HTTPError) {
        console.log("Message:", error.message);
        console.log("Status:", error.status);
        console.log("Body:", error.body);
    }
}
```

`body` contains the raw response body when available.

ID Token validation errors and JWT verification errors are also thrown by `parseClaims`. These may originate from the validation logic or the underlying `jose` library.

## Providers

o2js does not include provider implementations.

You can define your own provider using the `Provider` interface:

```typescript
export interface Provider {
    authURL: string;
    tokenURL: string;
    issuerURL?: string;
    jwksURL?: string;
}
```

- `authURL`: Authorization endpoint URL.
- `tokenURL`: Token endpoint URL.
- `issuerURL`: OpenID Connect issuer URL. Required for ID Token validation.
- `jwksURL`: JSON Web Key Set endpoint URL. Required for ID Token validation.

OAuth2-only providers do not need to define `issuerURL` or `jwksURL`.

## License

MIT