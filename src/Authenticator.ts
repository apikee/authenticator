import { NextFunction, Request, Response } from "express";
import jwt, { JwtPayload } from "jsonwebtoken";
import { cookieParser } from "./cookieParser";
import { AuthenticatorProps, TokenConfig } from "./interfaces";
import { MemoryStore } from "./stores";

export class Authenticator {
  constructor(protected _props: AuthenticatorProps) {
    if (!this._props.store) this._props.store = new MemoryStore();
    this._initExpiredTokenCleanup();
  }

  private _initExpiredTokenCleanup = () => {
    const timeout = setTimeout(async () => {
      await this._props.store?.clearExpiredTokens(this.validateToken);
      clearTimeout(timeout);
      this._initExpiredTokenCleanup();
    }, 1000 * 60 * 60);
  };

  private _getConfig = () => {
    return {
      accessExpiresIn: this._props.accessExpiresIn || 5 * 60,
      refreshExpiresIn: this._props.refreshExpiresIn || 24 * 60 * 60,
      sameSite: this._props.sameSite || "none",
      domain: this._props.domain || undefined,
    };
  };

  private _getCookie = (
    type: "accessToken" | "refreshToken",
    token: string,
    maxAge: number
  ) =>
    `${type}=${token}; HttpOnly; Secure; Max-Age: ${maxAge}; SameSite=${
      this._getConfig().sameSite
    }; ${this._getConfig().domain ? `Domain=${this._getConfig().domain}` : ""}`;

  private _getSignKey = (type: "access" | "refresh") => {
    if (type === "access") return this._props.accessKey;
    if (type === "refresh") return this._props.refreshKey;
    return "";
  };

  private _clearCookie = (res: Response) => {
    res.setHeader("set-cookie", [
      "accessToken=; Max-Age: 0;",
      "refreshToken=; Max-Age: 0;",
    ]);
  };

  private _clearCookieAndSendUnauthorized = (res: Response) => {
    this._clearCookie(res);
    return res.sendStatus(401);
  };

  validateToken = (
    type: "access" | "refresh",
    token: string
  ): JwtPayload | string | null => {
    try {
      const decoded = jwt.verify(token, this._getSignKey(type));
      return decoded as JwtPayload;
    } catch (error) {
      return null;
    }
  };

  generateToken = (type: "access" | "refresh", config: TokenConfig) => {
    return jwt.sign(config.payload || {}, this._getSignKey(type), {
      expiresIn: `${config.expiresIn}s`,
      subject: config.subject,
    });
  };

  createTokens =
    (replace: boolean = false) =>
    (_: Request, res: Response, next: NextFunction) => {
      const oldEnd = res.end;
      const oldSend = res.send;

      res.end = (cb?: () => void | undefined): Response<any> => {
        if (res.subject) {
          this.createSignInTokens(res, res.subject, replace, res?.payload);
        }

        res.end = oldEnd;
        return res.end(cb);
      };

      return next();
    };

  createSignInTokens = (
    res: Response,
    subject: string,
    replace: boolean = false,
    payload: any = {}
  ) => {
    if (!subject) throw new Error("Cannot generate tokens without subject");

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
      this._getCookie(
        "accessToken",
        accessToken,
        this._getConfig().accessExpiresIn
      ),
      this._getCookie(
        "refreshToken",
        refreshToken,
        this._getConfig().refreshExpiresIn
      ),
    ]);

    this._props.store!.addToken(refreshToken, subject, replace);

    return { accessToken, refreshToken };
  };

  checkForTokenReuse = (
    jwtPayload: JwtPayload,
    subject?: string
  ): { reuse: boolean } => {
    if (subject) return { reuse: false };

    const { sub } = jwtPayload;
    if (!sub) return { reuse: true };

    this._props.store?.deleteAllTokensForSubject(sub);

    return { reuse: true };
  };

  refreshTokens =
    (subjectLookup?: (subject: string) => Promise<any> | any) =>
    async (req: Request, res: Response, next: NextFunction) => {
      if (!req.headers.cookie) return res.sendStatus(401);

      const cookies = cookieParser(req.headers.cookie);
      if (!cookies.refreshToken) return res.sendStatus(401);

      const { refreshToken } = cookies;

      const validatedToken = this.validateToken("refresh", refreshToken);

      if (!validatedToken) return this._clearCookieAndSendUnauthorized(res);

      const subject = this._props.store?.findSubjectByToken(refreshToken);

      const { reuse } = this.checkForTokenReuse(
        validatedToken as JwtPayload,
        subject
      );

      if (reuse) return this._clearCookieAndSendUnauthorized(res);

      if (subject !== validatedToken.sub)
        return this._clearCookieAndSendUnauthorized(res);

      this.createSignInTokens(res, subject!, true);

      const lookupResult = subjectLookup ? await subjectLookup(subject!) : null;

      req.subject = lookupResult || subject;

      return next();
    };
}
