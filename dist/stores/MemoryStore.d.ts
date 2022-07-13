import { JwtPayload } from "jsonwebtoken";
import { Store } from "../stores";
export declare class MemoryStore extends Store {
    private _data;
    private _getTokenBySubject;
    addToken: (token: string, subject: string, replace?: boolean) => void;
    findSubjectByToken: (token: string) => string;
    deleteToken: (token: string) => void;
    deleteAllTokensForSubject: (subject: string) => void;
    clearExpiredTokens: (validateToken: (type: "access" | "refresh", token: string) => JwtPayload | string | null) => Promise<void>;
}
