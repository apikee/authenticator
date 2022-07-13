import { JwtPayload } from "jsonwebtoken";
export declare class Store {
    addToken: (token: string, subject: string, replace?: boolean) => void;
    findSubjectByToken: (token: string) => string;
    deleteToken: (token: string) => void;
    deleteAllTokensForSubject: (subject: string) => void;
    clearExpiredTokens: (validateToken: (type: "access" | "refresh", token: string) => JwtPayload | string | null) => Promise<void>;
}
