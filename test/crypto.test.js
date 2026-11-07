import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { generateRandomNonce, generateRandomPKCE, generateRandomState } from "../dist/index.js";

test("generateRandomState returns a 32-byte hex value", () => {
    const state = generateRandomState();
    assert.match(state, /^[0-9a-f]{64}$/);
    assert.notEqual(generateRandomState(), state);
});

test("generateRandomNonce returns an independently generated 32-byte hex value", () => {
    const nonce = generateRandomNonce();
    assert.match(nonce, /^[0-9a-f]{64}$/);
    assert.notEqual(generateRandomNonce(), nonce);
});

test("generateRandomPKCE returns a URL-safe verifier and matching SHA-256 challenge", () => {
    const { codeVerifier, codeChallenge } = generateRandomPKCE();

    assert.match(codeVerifier, /^[A-Za-z0-9_-]{43}$/);
    assert.match(codeChallenge, /^[A-Za-z0-9_-]{43}$/);
    assert.equal(
        codeChallenge,
        createHash("sha256").update(codeVerifier).digest("base64url"),
    );
    assert.notEqual(generateRandomPKCE().codeVerifier, codeVerifier);
});
