export interface Provider {
    authURL: string;
    tokenURL: string;
    issuerURL?: string;
    jwksURL?: string;
}