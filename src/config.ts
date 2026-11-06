export type ClientAuthMethod =
    | "client_secret_basic"
    | "client_secret_post";

export type Config = {
    clientID: string;
    clientSecret: string;
    redirectURL: string;
    clientAuthMethod?: ClientAuthMethod;
};