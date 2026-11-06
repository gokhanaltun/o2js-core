type ParseParamsCallback = (key: string, value: string) => void;

export function baseReservedParams(): Set<string> {
    return new Set([
        "client_id",
        "client_secret",
        "redirect_uri",
        "code",
        "refresh_token",
        "state",
        "response_type",
        "grant_type"
    ]);
}

export function extendReservedParams(extraReservedParams: string[] = []): Set<string> {
    const params = baseReservedParams();

    for (const param of extraReservedParams) {
        params.add(param);
    }

    return params;
}

export function parseParams(
    reservedParams: Set<string>,
    paramsData: Record<string, string>,
    callback: ParseParamsCallback
): void {
    for (const [key, value] of Object.entries(paramsData)) {
        if (reservedParams.has(key)) {
            continue;
        }

        callback(key, value);
    }
}