import type { Provider } from "./provider.js";
import type { Config } from "./config.js";
import type { ExchangeResponse } from "./response.js";

import { HTTPError } from "./errors.js";
import {
    parseParams,
    baseReservedParams,
} from "./params.js";

import {
    createRemoteJWKSet,
    jwtVerify,
    type JWTPayload,
} from "jose";

export type IDTokenClaims = JWTPayload & {
    iss: string;
    sub: string;
    aud: string | string[];
    exp: number;
    iat: number;
};

function encodeFormValue(value: string): string {
    return new URLSearchParams([["value", value]])
        .toString()
        .slice("value=".length);
}

export class OAuth2 {
    private jwks?: ReturnType<typeof createRemoteJWKSet>;

    constructor(
        private provider: Provider,
        private config: Config
    ) {
        this.validate();
    }

    authCodeURL(state: string, urlParams?: Record<string, string>): string {
        const params = new URLSearchParams();

        params.set("client_id", this.config.clientID);
        params.set("redirect_uri", this.config.redirectURL);
        params.set("response_type", "code");

        parseParams(
            baseReservedParams(),
            urlParams ?? {},
            (key, value) => {
                params.set(key, value);
            }
        );

        if (state !== "") {
            params.set("state", state);
        }

        const url = new URL(this.provider.authURL);

        params.forEach((value, key) => {
            url.searchParams.set(key, value);
        });

        return url.toString();
    }

    async exchangeAuthCode(code: string, tokenParams?: Record<string, string>): Promise<ExchangeResponse> {
        if (!code.trim()) {
            throw new Error("Code cannot be empty");
        }

        const params = new URLSearchParams();

        params.set("code", code);
        params.set("redirect_uri", this.config.redirectURL);
        params.set("grant_type", "authorization_code");

        return this.exchange(params, baseReservedParams(), tokenParams);
    }

    async exchangeRefreshToken(refreshToken: string, tokenParams?: Record<string, string>): Promise<ExchangeResponse> {
        if (!refreshToken.trim()) {
            throw new Error("Refresh token cannot be empty");
        }

        const params = new URLSearchParams();

        params.set("refresh_token", refreshToken);
        params.set("grant_type", "refresh_token");

        return this.exchange(
            params,
            baseReservedParams(),
            tokenParams
        );
    }

    private async exchange(
        params: URLSearchParams,
        reservedParams: Set<string>,
        tokenParams?: Record<string, string>
    ): Promise<ExchangeResponse> {

        parseParams(
            reservedParams,
            tokenParams ?? {},
            (key, value) => {
                params.set(key, value);
            }
        );

        const authMethod = this.config.clientAuthMethod ?? "client_secret_basic";

        const headers: Record<string, string> = {
            "Content-Type": "application/x-www-form-urlencoded",
        };

        if (authMethod === "client_secret_basic") {
            const credentials = Buffer.from(
                `${encodeFormValue(this.config.clientID)}:${encodeFormValue(this.config.clientSecret)}`,
                "utf8"
            ).toString("base64");

            headers["Authorization"] = `Basic ${credentials}`;
        } else {
            params.set("client_id", this.config.clientID);
            params.set("client_secret", this.config.clientSecret);
        }

        let response: Response;

        try {
            response = await fetch(this.provider.tokenURL, {
                method: "POST",
                headers,
                body: params.toString(),
            });
        } catch (error) {
            throw new HTTPError(
                "Exchange: failed to post token request",
                undefined,
                undefined,
                { cause: error }
            );
        }

        let raw: string;

        try {
            raw = await response.text();
        } catch (error) {
            throw new HTTPError(
                "Exchange: failed to read token response",
                response.status,
                undefined,
                { cause: error }
            );
        }

        if (!response.ok) {
            throw new HTTPError(
                `Exchange: token request failed with status ${response.status}`,
                response.status,
                raw
            );
        }

        let parsed: unknown;

        try {
            parsed = JSON.parse(raw);
        } catch (error) {
            throw new HTTPError(
                "Exchange: failed to parse token response",
                response.status,
                raw,
                { cause: error }
            );
        }

        if (
            typeof parsed !== "object" ||
            parsed === null ||
            Array.isArray(parsed)
        ) {
            throw new HTTPError(
                "Exchange: token response must be a JSON object",
                response.status,
                raw
            );
        }

        return {
            raw,
            data: parsed as Record<string, unknown>,
        };
    }

    async parseClaims(
        idToken: string,
        options?: {
            nonce?: string;
            maxAge?: number;
            trustedAudiences?: string[];
            algorithms?: ("RS256" | "PS256" | "ES256" | "ES384" | "ES512")[];
        }
    ): Promise<IDTokenClaims> {
        if (!idToken.trim()) {
            throw new Error("ID Token cannot be empty");
        }

        const issuer = this.provider.issuerURL;
        const jwksURL = this.provider.jwksURL;

        if (!issuer?.trim()) {
            throw new Error("Provider issuer URL is required");
        }

        if (!jwksURL?.trim()) {
            throw new Error("Provider JWKS URL is required");
        }

        if (
            options?.nonce !== undefined &&
            !options.nonce.trim()
        ) {
            throw new Error("Nonce cannot be empty");
        }

        if (
            options?.maxAge !== undefined &&
            (!Number.isFinite(options.maxAge) || options.maxAge < 0)
        ) {
            throw new Error("maxAge must be a non-negative number");
        }

        if (
            options?.trustedAudiences?.some(
                (audience) => !audience.trim()
            )
        ) {
            throw new Error("Trusted audiences cannot contain empty values");
        }

        const algorithms = options?.algorithms ?? ["RS256"];

        if (algorithms.length === 0) {
            throw new Error("At least one signing algorithm is required");
        }

        if (!this.jwks) {
            this.jwks = createRemoteJWKSet(new URL(jwksURL));
        }

        const { payload } = await jwtVerify(
            idToken,
            this.jwks,
            {
                issuer,
                audience: this.config.clientID,
                algorithms,
                clockTolerance: 5,
            }
        );

        // Subject
        if (
            typeof payload.sub !== "string" ||
            !payload.sub
        ) {
            throw new Error("Invalid ID Token: missing subject");
        }

        // Audience
        const audiences =
            typeof payload.aud === "string"
                ? [payload.aud]
                : payload.aud;

        if (
            !Array.isArray(audiences) ||
            audiences.length === 0 ||
            audiences.some(
                (audience) =>
                    typeof audience !== "string" ||
                    !audience
            )
        ) {
            throw new Error("Invalid ID Token: invalid audience");
        }

        const trustedAudiences = new Set([
            this.config.clientID,
            ...(options?.trustedAudiences ?? []),
        ]);

        if (
            audiences.some(
                (audience) => !trustedAudiences.has(audience)
            )
        ) {
            throw new Error("Invalid ID Token: untrusted audience");
        }

        // Expiration
        if (
            typeof payload.exp !== "number" ||
            !Number.isFinite(payload.exp)
        ) {
            throw new Error("Invalid ID Token: invalid expiration");
        }

        // Issued at
        if (
            typeof payload.iat !== "number" ||
            !Number.isFinite(payload.iat) ||
            payload.iat < 0
        ) {
            throw new Error("Invalid ID Token: invalid issued-at claim");
        }

        // Nonce
        if (options?.nonce !== undefined) {
            if (
                typeof payload.nonce !== "string" ||
                payload.nonce !== options.nonce
            ) {
                throw new Error("Invalid ID Token: nonce mismatch");
            }
        }

        // Authorized party
        if (audiences.length > 1 && typeof payload.azp !== "string") {
            throw new Error("Invalid ID Token: missing authorized party");
        }

        if (
            payload.azp !== undefined &&
            (
                typeof payload.azp !== "string" ||
                payload.azp !== this.config.clientID
            )
        ) {
            throw new Error("Invalid ID Token: authorized party mismatch");
        }

        // Authentication time
        if (options?.maxAge !== undefined) {
            if (typeof payload.auth_time !== "number") {
                throw new Error("Invalid ID Token: missing authentication time");
            }

            const now = Math.floor(Date.now() / 1000);
            const authTime = payload.auth_time;

            if (!Number.isFinite(authTime) || authTime < 0) {
                throw new Error("Invalid ID Token: invalid authentication time");
            }

            if (authTime > now + 5) {
                throw new Error("Invalid ID Token: authentication time is in the future");
            }

            if (now - authTime > options.maxAge + 5) {
                throw new Error("Invalid ID Token: authentication is too old");
            }
        }

        return payload as IDTokenClaims;
    }

    private validate(): void {
        if (!this.provider) {
            throw new Error("Provider cannot be null or undefined");
        }

        if (!this.config) {
            throw new Error("Config cannot be null or undefined");
        }

        if (!this.provider.authURL.trim()) {
            throw new Error("Provider authorization URL cannot be empty");
        }

        if (!this.provider.tokenURL.trim()) {
            throw new Error("Provider token URL cannot be empty");
        }

        if (!this.config.clientID.trim()) {
            throw new Error("Client ID cannot be empty");
        }

        if (!this.config.clientSecret.trim()) {
            throw new Error("Client secret cannot be empty");
        }

        if (!this.config.redirectURL.trim()) {
            throw new Error("Redirect URL cannot be empty");
        }

        if (
            this.config.clientAuthMethod !== undefined &&
            !["client_secret_basic", "client_secret_post"].includes(this.config.clientAuthMethod)
        ) {
            throw new Error("Unsupported client authentication method");
        }
    }
}
