import { Store } from "../stores/Store";
export interface AuthenticatorProps {
    accessKey: string;
    refreshKey: string;
    domain?: string;
    accessExpiresInSeconds?: number;
    refreshExpiresInSeconds?: number;
    sameSite?: "lax" | "none" | "strict";
    store?: Store;
}
