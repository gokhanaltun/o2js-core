# o2js

**A lightweight and provider-agnostic OAuth2 library for Node.js.**

o2js provides the core OAuth2 authorization code and refresh token flows.

It does not manage users, sessions, token storage, or database operations. It only handles OAuth2 mechanics and leaves the rest to your application.

## Installation

```bash
npm install @o2js/core
```

## Quick Start

First, define a provider:

```typescript
import type { Provider } from "@o2js/core";

class MyProvider implements Provider {
    authURL(): string {
        return "https://example.com/oauth/authorize";
    }

    tokenURL(): string {
        return "https://example.com/oauth/token";
    }
}
```

Create an OAuth2 client:

```typescript
import { OAuth2 } from "@o2js/core";

const oauth = new OAuth2(
    new MyProvider(),
    {
        clientID: "your-client-id",
        clientSecret: "your-client-secret",
        redirectURL: "https://yourapp.com/callback",
    }
);
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

You can pass these parameters directly to the relevant methods.

Additional authorization URL parameters:

```typescript
const url = oauth.authCodeURL(state, {
    scope: "profile email",
    prompt: "consent",
});
```

Additional token request parameters:

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

## State and PKCE

o2js provides helpers for generating random state values and PKCE parameters.

Generate a random state:

```typescript
import { generateRandomState } from "@o2js/core";

const state = generateRandomState();
```

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

State and PKCE values must be stored and managed by your application. o2js does not handle their storage, verification, or lifecycle.

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

HTTP and response parsing errors are represented by `HTTPError`.

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

## Providers

o2js does not include provider implementations.

You can implement the `Provider` interface yourself or use separate provider packages when available.

A provider only needs to implement:

```typescript
export interface Provider {
    authURL(): string;
    tokenURL(): string;
}
```

## License

MIT