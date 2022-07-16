import { JwtPayload } from "jsonwebtoken";
import { Store } from "@apikee/authenticator-common";
export declare class MemoryStore extends Store {
    private _data;
    addToken: (token: string, subject: string, replace?: boolean) => Promise<void>;
    findSubjectByToken: (token: string) => string;
    deleteToken: (token: string) => void;
    deleteAllTokensForSubject: (subject: string) => void;
    clearExpiredTokens: (validateToken: (type: "access" | "refresh", token: string) => JwtPayload | string | null) => Promise<void>;
}
