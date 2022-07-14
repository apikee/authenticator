"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.Authenticator = void 0;
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const cookieParser_1 = require("./cookieParser");
const stores_1 = require("./stores");
class Authenticator {
    _props;
    constructor(_props) {
        this._props = _props;
        if (!this._props.store)
            this._props.store = new stores_1.MemoryStore();
        this._initExpiredTokenCleanup();
    }
    _initExpiredTokenCleanup = () => {
        const timeout = setTimeout(async () => {
            await this._props.store?.clearExpiredTokens(this.validateToken);
            clearTimeout(timeout);
            this._initExpiredTokenCleanup();
        }, 1000 * 60 * 60);
    };
    _getConfig = () => {
        return {
            accessExpiresIn: this._props.accessExpiresIn || 5 * 60,
            refreshExpiresIn: this._props.refreshExpiresIn || 24 * 60 * 60,
            sameSite: this._props.sameSite || "none",
            domain: this._props.domain || undefined,
        };
    };
    _getCookie = (type, token, maxAge) => `${type}=${token}; HttpOnly; Secure; Max-Age: ${maxAge}; SameSite=${this._getConfig().sameSite}; ${this._getConfig().domain ? `Domain=${this._getConfig().domain}` : ""}`;
    _getSignKey = (type) => {
        if (type === "access")
            return this._props.accessKey;
        if (type === "refresh")
            return this._props.refreshKey;
        return "";
    };
    _clearCookie = (res) => {
        res.setHeader("set-cookie", [
            "accessToken=; Max-Age: 0;",
            "refreshToken=; Max-Age: 0;",
        ]);
    };
    _clearCookieAndSendUnauthorized = (res) => {
        this._clearCookie(res);
        return res.sendStatus(401);
    };
    validateToken = (type, token) => {
        try {
            const decoded = jsonwebtoken_1.default.verify(token, this._getSignKey(type));
            return decoded;
        }
        catch (error) {
            return null;
        }
    };
    generateToken = (type, config) => {
        return jsonwebtoken_1.default.sign({ payload: config.payload || {} }, this._getSignKey(type), {
            expiresIn: `${config.expiresIn}s`,
            subject: config.subject,
        });
    };
    createAccess = (replace = false) => {
        return (_, res, next) => {
            const oldEnd = res.end;
            res.end = (cb) => {
                if (res.subject) {
                    this.createSignInTokens(res, res.subject, replace, res?.payload);
                }
                res.end = oldEnd;
                return res.end(cb);
            };
            return next();
        };
    };
    createSignInTokens = (res, subject, replace = false, payload = {}) => {
        if (!subject)
            throw new Error("Cannot generate tokens without subject");
        const accessToken = this.generateToken("access", {
            subject,
            expiresIn: this._getConfig().accessExpiresIn,
            payload,
        });
        const refreshToken = this.generateToken("refresh", {
            subject,
            expiresIn: this._getConfig().refreshExpiresIn,
        });
        res.setHeader("set-cookie", [
            this._getCookie("accessToken", accessToken, this._getConfig().accessExpiresIn),
            this._getCookie("refreshToken", refreshToken, this._getConfig().refreshExpiresIn),
        ]);
        this._props.store.addToken(refreshToken, subject, replace);
        return { accessToken, refreshToken };
    };
    checkForTokenReuse = (jwtPayload, subject) => {
        if (subject)
            return { reuse: false };
        const { sub } = jwtPayload;
        if (!sub)
            return { reuse: true };
        this._props.store?.deleteAllTokensForSubject(sub);
        return { reuse: true };
    };
    refreshAccess = (subjectLookup) => {
        return async (req, res, next) => {
            if (!req.headers.cookie)
                return res.sendStatus(401);
            const cookies = (0, cookieParser_1.cookieParser)(req.headers.cookie);
            if (!cookies.refreshToken)
                return res.sendStatus(401);
            const { refreshToken, accessToken } = cookies;
            const validatedToken = this.validateToken("refresh", refreshToken);
            if (!validatedToken)
                return this._clearCookieAndSendUnauthorized(res);
            const subject = this._props.store?.findSubjectByToken(refreshToken);
            const { reuse } = this.checkForTokenReuse(validatedToken, subject);
            if (reuse)
                return this._clearCookieAndSendUnauthorized(res);
            if (subject !== validatedToken.sub)
                return this._clearCookieAndSendUnauthorized(res);
            const accessTokenDecoded = jsonwebtoken_1.default.decode(accessToken || "");
            this.createSignInTokens(res, subject, true, accessTokenDecoded?.payload);
            const lookupResult = subjectLookup ? await subjectLookup(subject) : null;
            req.subject = lookupResult || subject;
            req.payload = accessTokenDecoded?.payload;
            return next();
        };
    };
    validateAccess = (requireValidAccess = true, subjectLookup) => {
        return async (req, res, next) => {
            if (!req.headers.cookie) {
                if (requireValidAccess)
                    return res.sendStatus(401);
                return next();
            }
            const cookies = (0, cookieParser_1.cookieParser)(req.headers.cookie || "");
            if (!cookies.accessToken || !cookies.refreshToken) {
                if (requireValidAccess)
                    return res.sendStatus(401);
                return next();
            }
            const { accessToken, refreshToken } = cookies;
            const validatedAccess = this.validateToken("access", accessToken);
            const validatedRefresh = this.validateToken("refresh", refreshToken);
            if (!validatedAccess || !validatedRefresh) {
                if (requireValidAccess)
                    return res.sendStatus(401);
                return next();
            }
            const { reuse } = this.checkForTokenReuse(validatedRefresh, this._props.store?.findSubjectByToken(refreshToken));
            if (reuse)
                return this._clearCookieAndSendUnauthorized(res);
            const lookupResult = subjectLookup
                ? await subjectLookup(validatedAccess.sub)
                : null;
            req.subject = lookupResult || validatedAccess.sub;
            req.payload = validatedAccess?.payload;
            return next();
        };
    };
    revokeAccess = (subjectLookup) => {
        return async (req, res, next) => {
            if (!req.headers.cookie)
                return res.sendStatus(401);
            const cookies = (0, cookieParser_1.cookieParser)(req.headers.cookie);
            if (!cookies.refreshToken)
                return res.sendStatus(401);
            const { refreshToken, accessToken } = cookies;
            const validatedToken = this.validateToken("refresh", refreshToken);
            if (!validatedToken)
                return this._clearCookieAndSendUnauthorized(res);
            const subject = this._props.store?.findSubjectByToken(refreshToken);
            const { reuse } = this.checkForTokenReuse(validatedToken, subject);
            if (reuse)
                return this._clearCookieAndSendUnauthorized(res);
            if (subject !== validatedToken.sub)
                return this._clearCookieAndSendUnauthorized(res);
            const accessTokenDecoded = jsonwebtoken_1.default.decode(accessToken || "");
            const lookupResult = subjectLookup ? await subjectLookup(subject) : null;
            req.subject = lookupResult || subject;
            req.payload = accessTokenDecoded?.payload;
            this._clearCookie(res);
            return next();
        };
    };
}
exports.Authenticator = Authenticator;
