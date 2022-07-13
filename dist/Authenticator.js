"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.Authenticator = void 0;
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const cookieParser_1 = require("./cookieParser");
const MemoryStore_1 = require("./MemoryStore");
class Authenticator {
    _props;
    constructor(_props) {
        this._props = _props;
        if (!this._props.store)
            this._props.store = new MemoryStore_1.MemoryStore();
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
        return jsonwebtoken_1.default.sign(config.payload || {}, this._getSignKey(type), {
            expiresIn: `${config.expiresIn}s`,
            subject: config.subject,
        });
    };
    createTokens = (replace = false) => (_, res, next) => {
        const oldEnd = res.end;
        res.end = (data) => {
            if (res.subject) {
                this.createSignInTokens(res, res.subject, replace, res?.payload);
            }
            res.end = oldEnd;
            res.end(data);
        };
        return next();
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
    refreshTokens = (subjectLookup) => async (req, res, next) => {
        if (!req.headers.cookie)
            return res.sendStatus(401);
        const cookies = (0, cookieParser_1.cookieParser)(req.headers.cookie);
        if (!cookies.refreshToken)
            return res.sendStatus(401);
        const { refreshToken } = cookies;
        const validatedToken = this.validateToken("refresh", refreshToken);
        if (!validatedToken)
            return this._clearCookieAndSendUnauthorized(res);
        const subject = this._props.store?.findSubjectByToken(refreshToken);
        const { reuse } = this.checkForTokenReuse(validatedToken, subject);
        if (reuse)
            return this._clearCookieAndSendUnauthorized(res);
        if (subject !== validatedToken.sub)
            return this._clearCookieAndSendUnauthorized(res);
        this.createSignInTokens(res, subject, true);
        const lookupResult = subjectLookup ? await subjectLookup(subject) : null;
        // @ts-ignore
        req.subject = lookupResult || subject;
        return next();
    };
}
exports.Authenticator = Authenticator;
