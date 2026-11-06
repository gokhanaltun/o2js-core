export class HTTPError extends Error {
    constructor(
        message: string,
        public readonly status?: number,
        public readonly body?: string,
        options?: ErrorOptions
    ) {
        super(message, options);
        this.name = "HTTPError";
    }
}

