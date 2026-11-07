import test from "node:test";
import assert from "node:assert/strict";
import { generateKeyPair, exportJWK, SignJWT } from "jose";
import { OAuth2, HTTPError } from "../dist/index.js";

const config = {
    clientID: "client-123",
    clientSecret: "secret-456",
    redirectURL: "https://app.example/callback?from=test",
};

function makeOAuth2({ authURL = "https://provider.example/authorize", tokenURL = "https://provider.example/token", issuerURL, jwksURL, config: configOverrides = {} } = {}) {
    return new OAuth2({ authURL, tokenURL, issuerURL, jwksURL }, { ...config, ...configOverrides });
}

function makeProvider(authURL = "https://p.example/a", tokenURL = "https://p.example/t") {
    return { authURL, tokenURL };
}

function makeExchangeResponse(data = {}) {
    return { raw: JSON.stringify(data), data };
}

function withFetch(mock, run) {
    const originalFetch = globalThis.fetch;
    globalThis.fetch = mock;
    return Promise.resolve()
        .then(run)
        .finally(() => {
            globalThis.fetch = originalFetch;
        });
}

test("constructor rejects missing provider, config, and blank required values", () => {
    assert.throws(() => new OAuth2(null, config), /Provider cannot be null or undefined/);
    assert.throws(() => new OAuth2(makeProvider(), null), /Config cannot be null or undefined/);
    assert.throws(() => makeOAuth2({ authURL: "  " }), /Provider authorization URL cannot be empty/);
    assert.throws(() => makeOAuth2({ tokenURL: "  " }), /Provider token URL cannot be empty/);

    for (const [field, message] of [
        ["clientID", /Client ID cannot be empty/],
        ["clientSecret", /Client secret cannot be empty/],
        ["redirectURL", /Redirect URL cannot be empty/],
    ]) {
        assert.throws(
            () => new OAuth2(makeProvider(), { ...config, [field]: "  " }),
            message,
        );
    }

    assert.throws(
        () => makeOAuth2({ config: { clientAuthMethod: "client_secret_jwt" } }),
        /Unsupported client authentication method/,
    );
});

test("constructor validates endpoint and redirect URIs", () => {
    for (const [options, message] of [
        [{ authURL: "not-a-url" }, /Provider authorization URL must be an absolute URI/],
        [{ tokenURL: "http://provider.example/token" }, /Provider token URL must use HTTPS/],
        [{ authURL: "https://provider.example/authorize#fragment" }, /Provider authorization URL cannot contain a fragment/],
        [{ tokenURL: "https://user:pass@provider.example/token" }, /Provider token URL cannot contain credentials/],
        [{ config: { ...config, redirectURL: "/callback" } }, /Redirect URL must be an absolute URI/],
        [{ config: { ...config, redirectURL: "https://app.example/callback#fragment" } }, /Redirect URL cannot contain a fragment/],
        [{ issuerURL: "http://issuer.example" }, /Provider issuer URL must use HTTPS/],
        [{ jwksURL: "https://issuer.example/jwks#key" }, /Provider JWKS URL cannot contain a fragment/],
    ]) {
        assert.throws(() => makeOAuth2(options), message);
    }

    assert.throws(() => makeOAuth2({ authURL: 42 }), /Provider authorization URL must be a string/);
    assert.throws(() => new OAuth2(makeProvider(), { ...config, clientID: null }), /Client ID must be a string/);

    assert.doesNotThrow(() => new OAuth2(
        makeProvider("http://127.0.0.1:8080/authorize", "http://localhost:8080/token"),
        config,
    ));
});

test("authCodeURL sets OAuth parameters, encodes values, and retains provider query parameters", () => {
    const oauth = makeOAuth2({ authURL: "https://provider.example/authorize?tenant=acme" });
    const url = new URL(oauth.authCodeURL("state value", { scope: "profile email", prompt: "consent" }));

    assert.equal(url.origin + url.pathname, "https://provider.example/authorize");
    assert.equal(url.searchParams.get("tenant"), "acme");
    assert.equal(url.searchParams.get("client_id"), config.clientID);
    assert.equal(url.searchParams.get("redirect_uri"), config.redirectURL);
    assert.equal(url.searchParams.get("response_type"), "code");
    assert.equal(url.searchParams.get("state"), "state value");
    assert.equal(url.searchParams.get("scope"), "profile email");
    assert.equal(url.searchParams.get("prompt"), "consent");
});

test("authCodeURL omits empty state and ignores custom values for reserved parameters", () => {
    const url = new URL(makeOAuth2().authCodeURL("", {
        client_id: "attacker-value",
        response_type: "token",
        state: "custom-state",
        grant_type: "custom-grant",
    }));

    assert.equal(url.searchParams.has("state"), false);
    assert.equal(url.searchParams.get("client_id"), config.clientID);
    assert.equal(url.searchParams.get("response_type"), "code");
    assert.equal(url.searchParams.has("grant_type"), false);
});

test("exchangeAuthCode sends the authorization code form request and returns raw and parsed data", async () => {
    const raw = '{"access_token":"access-1","token_type":"Bearer","expires_in":3600}';
    await withFetch(async (url, options) => {
        assert.equal(url, "https://provider.example/token");
        assert.equal(options.method, "POST");
        assert.equal(options.headers["Content-Type"], "application/x-www-form-urlencoded");
        assert.equal(options.headers.Authorization, `Basic ${Buffer.from("client-123:secret-456").toString("base64")}`);
        const body = new URLSearchParams(options.body);
        assert.equal(body.has("client_id"), false);
        assert.equal(body.has("client_secret"), false);
        assert.equal(body.get("code"), "auth code");
        assert.equal(body.get("redirect_uri"), config.redirectURL);
        assert.equal(body.get("grant_type"), "authorization_code");
        assert.equal(body.get("code_verifier"), "verifier-value");
        assert.equal(body.has("refresh_token"), false);
        return new Response(raw, { status: 200 });
    }, async () => {
        const result = await makeOAuth2().exchangeAuthCode("auth code", { code_verifier: "verifier-value" });
        assert.deepEqual(result, { raw, data: { access_token: "access-1", token_type: "Bearer", expires_in: 3600 } });
    });
});

test("exchangeRefreshToken sends refresh grant parameters and accepts custom parameters", async () => {
    await withFetch(async (_url, options) => {
        assert.equal(options.headers.Authorization, `Basic ${Buffer.from("client-123:secret-456").toString("base64")}`);
        const body = new URLSearchParams(options.body);
        assert.equal(body.has("client_id"), false);
        assert.equal(body.has("client_secret"), false);
        assert.equal(body.get("refresh_token"), "refresh-1");
        assert.equal(body.has("redirect_uri"), false);
        assert.equal(body.get("grant_type"), "refresh_token");
        assert.equal(body.get("resource"), "https://api.example");
        assert.equal(body.has("code"), false);
        return new Response('{"access_token":"access-2","token_type":"Bearer"}', { status: 200 });
    }, async () => {
        const result = await makeOAuth2().exchangeRefreshToken("refresh-1", { resource: "https://api.example" });
        assert.deepEqual(result.data, { access_token: "access-2", token_type: "Bearer" });
    });
});

test("token methods reject empty or whitespace-only credentials before fetching", async () => {
    await withFetch(async () => assert.fail("fetch must not be called"), async () => {
        await assert.rejects(makeOAuth2().exchangeAuthCode("  "), /Code cannot be empty/);
        await assert.rejects(makeOAuth2().exchangeRefreshToken("\t"), /Refresh token cannot be empty/);
    });
});

test("client_secret_post sends credentials in the form body", async () => {
    const postConfig = { ...config, clientAuthMethod: "client_secret_post" };
    await withFetch(async (_url, options) => {
        assert.equal(options.headers.Authorization, undefined);
        const body = new URLSearchParams(options.body);
        assert.equal(body.get("client_id"), postConfig.clientID);
        assert.equal(body.get("client_secret"), postConfig.clientSecret);
        assert.equal(body.get("code"), "post-code");
        return new Response('{"access_token":"access","token_type":"Bearer"}', { status: 200 });
    }, async () => {
        await makeOAuth2({ config: { clientAuthMethod: "client_secret_post" } }).exchangeAuthCode("post-code");
    });
});

test("client_secret_basic form-encodes credentials before building the Basic header", async () => {
    const specialConfig = { ...config, clientID: "id: with space", clientSecret: "secret+value" };
    const encoded = `${new URLSearchParams([["v", specialConfig.clientID]]).toString().slice(2)}:${new URLSearchParams([["v", specialConfig.clientSecret]]).toString().slice(2)}`;
    await withFetch(async (_url, options) => {
        assert.equal(options.headers.Authorization, `Basic ${Buffer.from(encoded).toString("base64")}`);
        return new Response('{"access_token":"access","token_type":"Bearer"}', { status: 200 });
    }, async () => {
        const oauth = new OAuth2(
            makeProvider("https://provider.example/authorize", "https://provider.example/token"),
            specialConfig,
        );
        await oauth.exchangeAuthCode("code");
    });
});

test("custom token parameters cannot replace reserved OAuth parameters", async () => {
    await withFetch(async (_url, options) => {
        const body = new URLSearchParams(options.body);
        assert.equal(options.headers.Authorization, `Basic ${Buffer.from("client-123:secret-456").toString("base64")}`);
        assert.equal(body.has("client_id"), false);
        assert.equal(body.has("client_secret"), false);
        assert.equal(body.get("code"), "real-code");
        assert.equal(body.get("grant_type"), "authorization_code");
        return new Response('{"access_token":"access","token_type":"Bearer"}', { status: 200 });
    }, async () => {
        await makeOAuth2().exchangeAuthCode("real-code", {
            client_id: "fake-client",
            client_secret: "fake-secret",
            code: "fake-code",
            grant_type: "fake-grant",
        });
    });
});

test("non-2xx responses become HTTPError with status and raw body", async () => {
    await withFetch(async () => new Response('{"error":"invalid_grant"}', { status: 400 }), async () => {
        await assert.rejects(makeOAuth2().exchangeAuthCode("code"), (error) => {
            assert.ok(error instanceof HTTPError);
            assert.equal(error.name, "HTTPError");
            assert.equal(error.message, "Exchange: token request failed with status 400");
            assert.equal(error.status, 400);
            assert.equal(error.body, '{"error":"invalid_grant"}');
            return true;
        });
    });
});

test("network failures become HTTPError and preserve the original cause", async () => {
    const cause = new Error("offline");
    await withFetch(async () => { throw cause; }, async () => {
        await assert.rejects(makeOAuth2().exchangeRefreshToken("refresh"), (error) => {
            assert.ok(error instanceof HTTPError);
            assert.equal(error.message, "Exchange: failed to post token request");
            assert.equal(error.status, undefined);
            assert.equal(error.body, undefined);
            assert.equal(error.cause, cause);
            return true;
        });
    });
});

test("response body read failures become HTTPError with status and cause", async () => {
    const cause = new Error("cannot read body");
    const response = {
        ok: true,
        status: 200,
        text: async () => { throw cause; },
    };
    await withFetch(async () => response, async () => {
        await assert.rejects(makeOAuth2().exchangeAuthCode("code"), (error) => {
            assert.ok(error instanceof HTTPError);
            assert.equal(error.message, "Exchange: failed to read token response");
            assert.equal(error.status, 200);
            assert.equal(error.cause, cause);
            return true;
        });
    });
});

test("invalid JSON and non-object JSON responses become HTTPError", async (t) => {
    await t.test("invalid JSON", async () => {
        const raw = "not-json";
        await withFetch(async () => new Response(raw), async () => {
            await assert.rejects(makeOAuth2().exchangeAuthCode("code"), (error) => {
                assert.ok(error instanceof HTTPError);
                assert.equal(error.message, "Exchange: failed to parse token response");
                assert.equal(error.status, 200);
                assert.equal(error.body, raw);
                assert.ok(error.cause instanceof SyntaxError);
                return true;
            });
        });
    });

    for (const raw of ["null", "[]", '"token"', "42"]) {
        await t.test(`rejects ${raw}`, async () => {
            await withFetch(async () => new Response(raw), async () => {
                await assert.rejects(makeOAuth2().exchangeAuthCode("code"), (error) => {
                    assert.ok(error instanceof HTTPError);
                    assert.equal(error.message, "Exchange: token response must be a JSON object");
                    assert.equal(error.status, 200);
                    assert.equal(error.body, raw);
                    return true;
                });
            });
        });
    }
});

test("parseClaims validates signed ID tokens against a mocked JWKS and nonce", async () => {
    const { publicKey, privateKey } = await generateKeyPair("RS256");
    const jwk = await exportJWK(publicKey);
    jwk.kid = "test-key";
    jwk.alg = "RS256";
    jwk.use = "sig";
    const issuerURL = "https://issuer.example";
    const oauth = makeOAuth2({ issuerURL, jwksURL: "https://issuer.example/jwks" });
    const now = Math.floor(Date.now() / 1000);
    const token = await new SignJWT({ nonce: "expected-nonce", auth_time: now, email: "user@example.test" })
        .setProtectedHeader({ alg: "RS256", kid: "test-key" })
        .setIssuer(issuerURL)
        .setAudience(config.clientID)
        .setSubject("user-1")
        .setIssuedAt(now)
        .setExpirationTime(now + 300)
        .sign(privateKey);

    await withFetch(async (url) => {
        assert.equal(url, "https://issuer.example/jwks");
        return new Response(JSON.stringify({ keys: [jwk] }), { headers: { "content-type": "application/json" } });
    }, async () => {
        const claims = await oauth.parseClaims(makeExchangeResponse({ id_token: token }), { nonce: "expected-nonce", maxAge: 60 });
        assert.equal(claims.sub, "user-1");
        assert.equal(claims.iss, issuerURL);
        assert.equal(claims.nonce, "expected-nonce");
        assert.equal(claims.email, "user@example.test");
        await assert.rejects(oauth.parseClaims(makeExchangeResponse({ id_token: token }), { nonce: "wrong-nonce" }), /nonce mismatch/);
        await assert.rejects(oauth.parseClaims(makeExchangeResponse({ id_token: token })), /Expected nonce must be provided/);
    });
});

test("parseClaims requires an expected nonce when the token has none", async () => {
    const { publicKey, privateKey } = await generateKeyPair("RS256");
    const jwk = await exportJWK(publicKey);
    jwk.kid = "nonce-test-key";
    const issuerURL = "https://nonce-issuer.example";
    const oauth = makeOAuth2({ issuerURL, jwksURL: "https://nonce-issuer.example/jwks" });
    const now = Math.floor(Date.now() / 1000);
    const token = await new SignJWT({})
        .setProtectedHeader({ alg: "RS256", kid: jwk.kid })
        .setIssuer(issuerURL)
        .setAudience(config.clientID)
        .setSubject("user-2")
        .setIssuedAt(now)
        .setExpirationTime(now + 300)
        .sign(privateKey);

    await withFetch(async () => new Response(JSON.stringify({ keys: [jwk] })), async () => {
        await assert.rejects(oauth.parseClaims(makeExchangeResponse({ id_token: token }), { nonce: "expected" }), /missing nonce/);
    });
});

test("parseClaims applies OIDC issuer, audience, signature, and authorized-party checks", async () => {
    const { publicKey, privateKey } = await generateKeyPair("RS256");
    const jwk = await exportJWK(publicKey);
    jwk.kid = "protocol-check-key";
    const issuerURL = "https://protocol-issuer.example";
    const oauth = makeOAuth2({ issuerURL, jwksURL: "https://protocol-issuer.example/jwks" });
    const now = Math.floor(Date.now() / 1000);

    async function token({ issuer = issuerURL, audience = config.clientID, azp, subject = "user-3" } = {}) {
        const jwt = new SignJWT({ ...(azp === undefined ? {} : { azp }) })
            .setProtectedHeader({ alg: "RS256", kid: jwk.kid })
            .setIssuer(issuer)
            .setAudience(audience)
            .setSubject(subject)
            .setIssuedAt(now)
            .setExpirationTime(now + 300);
        return jwt.sign(privateKey);
    }

    await withFetch(async () => new Response(JSON.stringify({ keys: [jwk] })), async () => {
        const valid = await token();
        assert.equal((await oauth.parseClaims(makeExchangeResponse({ id_token: valid }))).sub, "user-3");

        await assert.rejects(oauth.parseClaims(makeExchangeResponse({ id_token: await token({ issuer: "https://attacker.example" }) })));
        await assert.rejects(oauth.parseClaims(makeExchangeResponse({ id_token: await token({ audience: "another-client" }) })));

        const multiAudience = await token({ audience: [config.clientID, "api.example"], azp: config.clientID });
        assert.equal(
            (await oauth.parseClaims(makeExchangeResponse({ id_token: multiAudience }), { trustedAudiences: ["api.example"] })).azp,
            config.clientID,
        );
        await assert.rejects(
            oauth.parseClaims(makeExchangeResponse({ id_token: await token({ audience: [config.clientID, "api.example"] }) }), { trustedAudiences: ["api.example"] }),
            /missing authorized party/,
        );
        await assert.rejects(
            oauth.parseClaims(makeExchangeResponse({ id_token: await token({ audience: [config.clientID, "api.example"], azp: "another-client" }) }), { trustedAudiences: ["api.example"] }),
            /authorized party mismatch/,
        );

        const [header, payload, signature] = valid.split(".");
        const alteredPayload = Buffer.from(JSON.stringify({ iss: issuerURL, sub: "forged", aud: config.clientID, exp: now + 300, iat: now })).toString("base64url");
        await assert.rejects(oauth.parseClaims(makeExchangeResponse({ id_token: `${header}.${alteredPayload}.${signature}` })));
    });
});

test("token exchange preserves required OAuth response fields and provider-specific extensions", async () => {
    const raw = '{"provider_field":true,"access_token":"access","token_type":"Bearer"}';
    await withFetch(async () => new Response(raw), async () => {
        assert.deepEqual(await makeOAuth2().exchangeAuthCode("code"), {
            raw,
            data: { provider_field: true, access_token: "access", token_type: "Bearer" },
        });
    });
});

test("successful OAuth token responses require non-empty access_token and token_type", async (t) => {
    for (const raw of [
        '{"access_token":"access"}',
        '{"token_type":"Bearer"}',
        '{"access_token":"","token_type":"Bearer"}',
        '{"access_token":"access","token_type":""}',
        '{"access_token":42,"token_type":"Bearer"}',
        '{"access_token":"access","token_type":42}',
    ]) {
        await t.test(raw, async () => {
            await withFetch(async () => new Response(raw), async () => {
                await assert.rejects(makeOAuth2().exchangeAuthCode("code"), (error) => {
                    assert.ok(error instanceof HTTPError);
                    assert.equal(error.message, "Exchange: invalid token response");
                    assert.equal(error.status, 200);
                    assert.equal(error.body, raw);
                    return true;
                });
            });
        });
    }
});

test("OAuth and provider-specific error bodies become HTTPError even on successful HTTP status", async (t) => {
    for (const [raw, expectedMessage] of [
        ['{"error":"invalid_grant","error_description":"Code expired"}', "Exchange: Code expired"],
        ['{"error":"invalid_client"}', "Exchange: invalid_client"],
        ['{"ok":false}', "Exchange: Token request failed"],
        ['{"error":42,"ok":false}', "Exchange: Token request failed"],
    ]) {
        await t.test(expectedMessage, async () => {
            await withFetch(async () => new Response(raw, { status: 200 }), async () => {
                await assert.rejects(makeOAuth2().exchangeAuthCode("code"), (error) => {
                    assert.ok(error instanceof HTTPError);
                    assert.equal(error.message, expectedMessage);
                    assert.equal(error.status, 200);
                    assert.equal(error.body, raw);
                    return true;
                });
            });
        });
    }
});

test("parseClaims rejects invalid inputs and missing OIDC provider metadata before network access", async () => {
    const oauth = makeOAuth2({ issuerURL: "https://issuer.example", jwksURL: "https://issuer.example/jwks" });
    const response = makeExchangeResponse({ id_token: "token" });
    await assert.rejects(oauth.parseClaims(makeExchangeResponse({ id_token: "  " })), /ID Token is missing or invalid/);
    await assert.rejects(oauth.parseClaims(response, { nonce: " " }), /Nonce cannot be empty/);
    await assert.rejects(oauth.parseClaims(response, { maxAge: -1 }), /maxAge must be a non-negative number/);
    await assert.rejects(oauth.parseClaims(response, { maxAge: Number.POSITIVE_INFINITY }), /maxAge must be a non-negative number/);
    await assert.rejects(oauth.parseClaims(response, { trustedAudiences: [" "] }), /Trusted audiences cannot contain empty values/);
    await assert.rejects(oauth.parseClaims(response, { algorithms: [] }), /At least one signing algorithm is required/);
    await assert.rejects(oauth.parseClaims(makeExchangeResponse({ id_token: 42 })), /ID Token is missing or invalid/);
    await assert.rejects(oauth.parseClaims(makeExchangeResponse({ id_token: null })), /ID Token is missing or invalid/);
    await assert.rejects(makeOAuth2({ jwksURL: "https://issuer.example/jwks" }).parseClaims(response), /Provider issuer URL is required/);
    await assert.rejects(makeOAuth2({ issuerURL: "https://issuer.example" }).parseClaims(response), /Provider JWKS URL is required/);
    await assert.rejects(oauth.parseClaims(makeExchangeResponse()), /ID Token is missing or invalid/);
});
