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
        if (!this._props.store) {
            this._props.store = new stores_1.MemoryStore();
        }
        if (!this._props.rejectedAccessHandler) {
            this._props.rejectedAccessHandler = (_, res) => res.sendStatus(401);
        }
        if (!this._props.cleanupEveryMs) {
            this._props.cleanupEveryMs = 1000 * 60 * 60;
        }
        this._initExpiredTokenCleanup();
    }
    _initExpiredTokenCleanup = () => {
        const timeout = setTimeout(async () => {
            await this._props.store?.clearExpiredTokens(this._validateToken);
            clearTimeout(timeout);
            this._initExpiredTokenCleanup();
        }, this._props.cleanupEveryMs);
    };
    _getConfig = () => {
        return {
            accessExpiresInSeconds: this._props.accessExpiresInSeconds || 5 * 60,
            refreshExpiresInSeconds: this._props.refreshExpiresInSeconds || 24 * 60 * 60,
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
    _clearCookieAndSendUnauthorized = async (req, res, next, token) => {
        await this._props.store?.deleteToken(token);
        this._clearCookie(res);
        return this._props.rejectedAccessHandler(req, res, next);
    };
    _validateToken = (type, token) => {
        try {
            const decoded = jsonwebtoken_1.default.verify(token, this._getSignKey(type));
            return decoded;
        }
        catch (error) {
            return null;
        }
    };
    _generateToken = (type, config) => {
        return jsonwebtoken_1.default.sign({ payload: config.payload || {} }, this._getSignKey(type), {
            expiresIn: `${config.expiresIn}s`,
            subject: config.subject,
        });
    };
    createAccess = (replace = false) => {
        return (_, res, next) => {
            const oldEnd = res.end;
            res.end = (cb) => {
                if (res.locals.subject) {
                    this._createSignInTokens(res, res.locals.subject, replace, res.locals?.payload);
                }
                res.end = oldEnd;
                return res.end(cb);
            };
            return next();
        };
    };
    _createSignInTokens = (res, subject, replace = false, payload = {}) => {
        if (!subject)
            throw new Error("Cannot generate tokens without subject");
        const accessToken = this._generateToken("access", {
            subject,
            expiresIn: this._getConfig().accessExpiresInSeconds,
            payload,
        });
        const refreshToken = this._generateToken("refresh", {
            subject,
            expiresIn: this._getConfig().refreshExpiresInSeconds,
        });
        res.setHeader("set-cookie", [
            this._getCookie("accessToken", accessToken, this._getConfig().accessExpiresInSeconds),
            this._getCookie("refreshToken", refreshToken, this._getConfig().refreshExpiresInSeconds),
        ]);
        this._props.store.addToken(refreshToken, subject, replace);
        return { accessToken, refreshToken };
    };
    _checkForTokenReuse = async (jwtPayload, subject) => {
        if (subject)
            return { reuse: false };
        const { sub } = jwtPayload;
        if (!sub)
            return { reuse: true };
        await this._props.store?.deleteAllTokensForSubject(sub);
        return { reuse: true };
    };
    refreshAccess = (subjectLookup) => {
        return async (req, res, next) => {
            if (!req.headers.cookie)
                return this._props.rejectedAccessHandler(req, res, next);
            const cookies = (0, cookieParser_1.cookieParser)(req.headers.cookie);
            if (!cookies.refreshToken)
                return this._props.rejectedAccessHandler(req, res, next);
            const { refreshToken, accessToken } = cookies;
            const validatedToken = this._validateToken("refresh", refreshToken);
            if (!validatedToken)
                return this._clearCookieAndSendUnauthorized(req, res, next, refreshToken);
            const subject = await this._props.store?.findSubjectByToken(refreshToken);
            const { reuse } = await this._checkForTokenReuse(validatedToken, subject);
            if (reuse)
                return this._clearCookieAndSendUnauthorized(req, res, next, refreshToken);
            if (subject !== validatedToken.sub)
                return this._clearCookieAndSendUnauthorized(req, res, next, refreshToken);
            const accessTokenDecoded = jsonwebtoken_1.default.decode(accessToken || "");
            await this._props.store?.deleteToken(refreshToken);
            this._createSignInTokens(res, subject, false, accessTokenDecoded?.payload);
            const lookupResult = subjectLookup ? await subjectLookup(subject) : null;
            res.locals.subject = lookupResult || subject;
            res.locals.payload = accessTokenDecoded?.payload;
            return next();
        };
    };
    validateAccess = (requireValidAccess = true, subjectLookup) => {
        return async (req, res, next) => {
            if (!req.headers.cookie) {
                if (requireValidAccess)
                    return this._props.rejectedAccessHandler(req, res, next);
                return next();
            }
            const cookies = (0, cookieParser_1.cookieParser)(req.headers.cookie || "");
            if (!cookies.accessToken || !cookies.refreshToken) {
                if (requireValidAccess)
                    return this._props.rejectedAccessHandler(req, res, next);
                return next();
            }
            const { accessToken, refreshToken } = cookies;
            const validatedAccess = this._validateToken("access", accessToken);
            const validatedRefresh = this._validateToken("refresh", refreshToken);
            if (!validatedAccess || !validatedRefresh) {
                if (requireValidAccess)
                    return this._props.rejectedAccessHandler(req, res, next);
                return next();
            }
            const { reuse } = await this._checkForTokenReuse(validatedRefresh, (await this._props.store?.findSubjectByToken(refreshToken)));
            if (reuse)
                return this._clearCookieAndSendUnauthorized(req, res, next, refreshToken);
            const lookupResult = subjectLookup
                ? await subjectLookup(validatedAccess.sub)
                : null;
            res.locals.subject = lookupResult || validatedAccess.sub;
            res.locals.payload = validatedAccess?.payload;
            return next();
        };
    };
    revokeAccess = (subjectLookup) => {
        return async (req, res, next) => {
            if (!req.headers.cookie)
                return this._props.rejectedAccessHandler(req, res, next);
            const cookies = (0, cookieParser_1.cookieParser)(req.headers.cookie);
            if (!cookies.refreshToken)
                return this._props.rejectedAccessHandler(req, res, next);
            const { refreshToken, accessToken } = cookies;
            const validatedToken = this._validateToken("refresh", refreshToken);
            if (!validatedToken)
                return this._clearCookieAndSendUnauthorized(req, res, next, refreshToken);
            const subject = await this._props.store?.findSubjectByToken(refreshToken);
            const { reuse } = await this._checkForTokenReuse(validatedToken, subject);
            if (reuse)
                return this._clearCookieAndSendUnauthorized(req, res, next, refreshToken);
            if (subject !== validatedToken.sub)
                return this._clearCookieAndSendUnauthorized(req, res, next, refreshToken);
            await this._props.store?.deleteToken(refreshToken);
            const accessTokenDecoded = jsonwebtoken_1.default.decode(accessToken || "");
            const lookupResult = subjectLookup ? await subjectLookup(subject) : null;
            res.locals.subject = lookupResult || subject;
            res.locals.payload = accessTokenDecoded?.payload;
            this._clearCookie(res);
            return next();
        };
    };
}
exports.Authenticator = Authenticator;
