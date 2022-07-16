import { JwtPayload } from "jsonwebtoken";
import { Store } from "@apikee/authenticator-common";

export class MemoryStore extends Store {
  private _data: Record<string, string> = {};

  addToken = async (
    token: string,
    subject: string,
    replace: boolean = false
  ): Promise<void> => {
    if (replace) {
      const usedTokens = Object.keys(this._data).filter(
        (token) => this._data[token] === subject
      );

      await Promise.all(usedTokens.map((token) => this.deleteToken(token)));
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
