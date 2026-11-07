import { randomBytes, createHash } from "node:crypto";

export type PKCE = {
    codeVerifier: string;
    codeChallenge: string;
};

export function generateRandomState(): string {
    return randomBytes(32).toString("hex");
}

export function generateRandomNonce(): string {
    return generateRandomState();
}

export function generateRandomPKCE(): PKCE {
    const codeVerifier = randomBytes(32).toString("base64url");

    const codeChallenge = createHash("sha256")
        .update(codeVerifier)
        .digest("base64url");

    return {
        codeVerifier,
        codeChallenge,
    };
}
