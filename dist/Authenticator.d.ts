import { NextFunction, Request, Response } from "express";
import { AuthenticatorProps } from "./interfaces";
import { SubjectLookup } from "./types";
export declare class Authenticator {
    private _props;
    constructor(_props: AuthenticatorProps);
    private _initExpiredTokenCleanup;
    private _getConfig;
    private _getCookie;
    private _getSignKey;
    private _clearCookie;
    private _clearCookieAndSendUnauthorized;
    private _validateToken;
    private _generateToken;
    createAccess: (replace?: boolean) => (_: Request, res: Response, next: NextFunction) => void;
    private _createSignInTokens;
    private _checkForTokenReuse;
    refreshAccess: (subjectLookup?: SubjectLookup | undefined) => (req: Request, res: Response, next: NextFunction) => Promise<void>;
    validateAccess: (requireValidAccess?: boolean, subjectLookup?: SubjectLookup | undefined) => (req: Request, res: Response, next: NextFunction) => Promise<void>;
    revokeAccess: (subjectLookup?: SubjectLookup | undefined) => (req: Request, res: Response, next: NextFunction) => Promise<void>;
}
