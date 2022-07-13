import { JwtPayload } from "jsonwebtoken";
import { Store } from "./interfaces";
export declare class MemoryStore implements Store {
    private _data;
    private _getTokenBySubject;
    addToken: (token: string, subject: string, replace?: boolean) => void;
    findSubjectByToken: (token: string) => string;
    deleteToken: (token: string) => void;
    deleteAllTokensForSubject: (subject: string) => void;
    clearExpiredTokens: (validateToken: (type: "access" | "refresh", token: string) => JwtPayload | string | null) => Promise<void>;
}
