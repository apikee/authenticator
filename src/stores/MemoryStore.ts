import { JwtPayload } from "jsonwebtoken";
import { Store } from "../stores";

export class MemoryStore extends Store {
  private _data: Record<string, string> = {};

  private _getTokenBySubject = (subject: string): string | undefined => {
    return Object.keys(this._data).find((key) => this._data[key] === subject);
  };

  addToken = (
    token: string,
    subject: string,
    replace: boolean = false
  ): void => {
    if (replace) {
      const usedToken = this._getTokenBySubject(subject);
      usedToken && this.deleteToken(usedToken);
    }

    this._data[token] = subject;
  };

  findSubjectByToken = (token: string): string => {
    return this._data[token];
  };

  deleteToken = (token: string): void => {
    delete this._data[token];
  };

  deleteAllTokensForSubject = (subject: string): void => {
    Object.keys(this._data)
      .filter((key) => this._data[key] === subject)
      .forEach((token) => this.deleteToken(token));
  };

  clearExpiredTokens = async (
    validateToken: (
      type: "access" | "refresh",
      token: string
    ) => JwtPayload | string | null
  ): Promise<void> => {
    await Promise.all(
      Object.keys(this._data).map((token) => {
        if (!validateToken("refresh", token)) {
          this.deleteToken(token);
        }
      })
    );
  };
}