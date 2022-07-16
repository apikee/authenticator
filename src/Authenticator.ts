import { NextFunction, Request, Response } from "express";
import jwt, { JwtPayload } from "jsonwebtoken";
import { cookieParser } from "./cookieParser";
import { AuthenticatorProps, TokenConfig } from "./interfaces";
import { MemoryStore } from "./stores";
import { SubjectLookup } from "./types";

export class Authenticator {
  constructor(private _props: AuthenticatorProps) {
    if (!this._props.store) {
      this._props.store = new MemoryStore();
    }

    if (!this._props.rejectedAccessHandler) {
      this._props.rejectedAccessHandler = (_, res) => res.sendStatus(401);
    }

    if (!this._props.cleanupEveryMs) {
      this._props.cleanupEveryMs = 1000 * 60 * 60;
    }

    this._initExpiredTokenCleanup();
  }

  private _initExpiredTokenCleanup = () => {
    const timeout = setTimeout(async () => {
      await this._props.store?.clearExpiredTokens(this._validateToken);
      clearTimeout(timeout);
      this._initExpiredTokenCleanup();
    }, this._props.cleanupEveryMs);
  };

  private _getConfig = () => {
    return {
      accessExpiresInSeconds: this._props.accessExpiresInSeconds || 5 * 60,
      refreshExpiresInSeconds:
        this._props.refreshExpiresInSeconds || 24 * 60 * 60,
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

  private _clearCookieAndSendUnauthorized = async (
    req: Request,
    res: Response,
    next: NextFunction,
    token: string
  ) => {
    await this._props.store?.deleteToken(token);
    this._clearCookie(res);
    return this._props.rejectedAccessHandler!(req, res, next);
  };

  private _validateToken = (
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

  private _generateToken = (
    type: "access" | "refresh",
    config: TokenConfig
  ) => {
    return jwt.sign({ payload: config.payload || {} }, this._getSignKey(type), {
      expiresIn: `${config.expiresIn}s`,
      subject: config.subject,
    });
  };

  createAccess = (replace: boolean = false) => {
    return (_: Request, res: Response, next: NextFunction) => {
      const oldEnd = res.end;

      res.end = (cb?: () => void | undefined): Response<any> => {
        if (res.locals.subject) {
          this._createSignInTokens(
            res,
            res.locals.subject,
            replace,
            res.locals?.payload
          );
        }

        res.end = oldEnd;
        return res.end(cb);
      };

      return next();
    };
  };

  private _createSignInTokens = (
    res: Response,
    subject: string,
    replace: boolean = false,
    payload: any = {}
  ) => {
    if (!subject) throw new Error("Cannot generate tokens without subject");

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
      this._getCookie(
        "accessToken",
        accessToken,
        this._getConfig().accessExpiresInSeconds
      ),
      this._getCookie(
        "refreshToken",
        refreshToken,
        this._getConfig().refreshExpiresInSeconds
      ),
    ]);

    this._props.store!.addToken(refreshToken, subject, replace);

    return { accessToken, refreshToken };
  };

  private _checkForTokenReuse = async (
    jwtPayload: JwtPayload,
    subject?: string
  ): Promise<{ reuse: boolean }> => {
    if (subject) return { reuse: false };

    const { sub } = jwtPayload;
    if (!sub) return { reuse: true };

    await this._props.store?.deleteAllTokensForSubject(sub);

    return { reuse: true };
  };

  refreshAccess = (subjectLookup?: SubjectLookup) => {
    return async (req: Request, res: Response, next: NextFunction) => {
      if (!req.headers.cookie)
        return this._props.rejectedAccessHandler!(req, res, next);

      const cookies = cookieParser(req.headers.cookie);
      if (!cookies.refreshToken)
        return this._props.rejectedAccessHandler!(req, res, next);

      const { refreshToken, accessToken } = cookies;

      const validatedToken = this._validateToken("refresh", refreshToken);

      if (!validatedToken)
        return this._clearCookieAndSendUnauthorized(
          req,
          res,
          next,
          refreshToken
        );

      const subject = await this._props.store?.findSubjectByToken(refreshToken);

      const { reuse } = await this._checkForTokenReuse(
        validatedToken as JwtPayload,
        subject as string
      );

      if (reuse)
        return this._clearCookieAndSendUnauthorized(
          req,
          res,
          next,
          refreshToken
        );

      if (subject !== validatedToken.sub)
        return this._clearCookieAndSendUnauthorized(
          req,
          res,
          next,
          refreshToken
        );

      const accessTokenDecoded = jwt.decode(accessToken || "") as any;

      await this._props.store?.deleteToken(refreshToken);

      this._createSignInTokens(
        res,
        subject!,
        false,
        accessTokenDecoded?.payload
      );

      const lookupResult = subjectLookup ? await subjectLookup(subject!) : null;

      res.locals.subject = lookupResult || subject;
      res.locals.payload = accessTokenDecoded?.payload;

      return next();
    };
  };

  validateAccess = (
    requireValidAccess: boolean = true,
    subjectLookup?: SubjectLookup
  ) => {
    return async (req: Request, res: Response, next: NextFunction) => {
      if (!req.headers.cookie) {
        if (requireValidAccess)
          return this._props.rejectedAccessHandler!(req, res, next);
        return next();
      }

      const cookies = cookieParser(req.headers.cookie || "");

      if (!cookies.accessToken || !cookies.refreshToken) {
        if (requireValidAccess)
          return this._props.rejectedAccessHandler!(req, res, next);
        return next();
      }

      const { accessToken, refreshToken } = cookies;

      const validatedAccess = this._validateToken("access", accessToken);
      const validatedRefresh = this._validateToken("refresh", refreshToken);

      if (!validatedAccess || !validatedRefresh) {
        if (requireValidAccess)
          return this._props.rejectedAccessHandler!(req, res, next);
        return next();
      }

      const { reuse } = await this._checkForTokenReuse(
        validatedRefresh as JwtPayload,
        (await this._props.store?.findSubjectByToken(refreshToken)) as string
      );

      if (reuse)
        return this._clearCookieAndSendUnauthorized(
          req,
          res,
          next,
          refreshToken
        );

      const lookupResult = subjectLookup
        ? await subjectLookup(validatedAccess.sub as string)
        : null;

      res.locals.subject = lookupResult || validatedAccess.sub;
      res.locals.payload = (validatedAccess as any)?.payload;

      return next();
    };
  };

  revokeAccess = (subjectLookup?: SubjectLookup) => {
    return async (req: Request, res: Response, next: NextFunction) => {
      if (!req.headers.cookie)
        return this._props.rejectedAccessHandler!(req, res, next);

      const cookies = cookieParser(req.headers.cookie);
      if (!cookies.refreshToken)
        return this._props.rejectedAccessHandler!(req, res, next);

      const { refreshToken, accessToken } = cookies;

      const validatedToken = this._validateToken("refresh", refreshToken);

      if (!validatedToken)
        return this._clearCookieAndSendUnauthorized(
          req,
          res,
          next,
          refreshToken
        );

      const subject = await this._props.store?.findSubjectByToken(refreshToken);

      const { reuse } = await this._checkForTokenReuse(
        validatedToken as JwtPayload,
        subject as string
      );

      if (reuse)
        return this._clearCookieAndSendUnauthorized(
          req,
          res,
          next,
          refreshToken
        );

      if (subject !== validatedToken.sub)
        return this._clearCookieAndSendUnauthorized(
          req,
          res,
          next,
          refreshToken
        );

      await this._props.store?.deleteToken(refreshToken);

      const accessTokenDecoded = jwt.decode(accessToken || "") as any;

      const lookupResult = subjectLookup ? await subjectLookup(subject!) : null;

      res.locals.subject = lookupResult || subject;
      res.locals.payload = accessTokenDecoded?.payload;

      this._clearCookie(res);

      return next();
    };
  };
}
