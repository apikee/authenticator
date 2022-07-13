import { Store } from "../stores/Store";
export interface AuthenticatorProps {
    accessKey: string;
    refreshKey: string;
    domain?: string;
    accessExpiresIn?: number;
    refreshExpiresIn?: number;
    sameSite?: "lax" | "none" | "strict";
    store?: Store;
}
