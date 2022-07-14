import { NextFunction, Request, Response } from "express";
import { JwtPayload } from "jsonwebtoken";
import { AuthenticatorProps, TokenConfig } from "./interfaces";
import { SubjectLookup } from "./types";
export declare class Authenticator {
    protected _props: AuthenticatorProps;
    constructor(_props: AuthenticatorProps);
    private _initExpiredTokenCleanup;
    private _getConfig;
    private _getCookie;
    private _getSignKey;
    private _clearCookie;
    private _clearCookieAndSendUnauthorized;
    validateToken: (type: "access" | "refresh", token: string) => JwtPayload | string | null;
    generateToken: (type: "access" | "refresh", config: TokenConfig) => string;
    createAccess: (replace?: boolean) => (_: Request, res: Response, next: NextFunction) => void;
    createSignInTokens: (res: Response, subject: string, replace?: boolean, payload?: any) => {
        accessToken: string;
        refreshToken: string;
    };
    checkForTokenReuse: (jwtPayload: JwtPayload, subject?: string | undefined) => {
        reuse: boolean;
    };
    refreshAccess: (subjectLookup?: SubjectLookup | undefined) => (req: Request, res: Response, next: NextFunction) => Promise<void | Response<any, Record<string, any>>>;
    validateAccess: (requireValidAccess?: boolean, subjectLookup?: SubjectLookup | undefined) => (req: Request, res: Response, next: NextFunction) => Promise<void | Response<any, Record<string, any>>>;
    revokeAccess: (subjectLookup?: SubjectLookup | undefined) => (req: Request, res: Response, next: NextFunction) => Promise<void | Response<any, Record<string, any>>>;
}
